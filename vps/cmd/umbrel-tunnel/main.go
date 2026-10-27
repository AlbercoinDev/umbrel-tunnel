// Command umbrel-tunnel is the VPS control plane and administration CLI.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"umbrel-tunnel/internal/backup"
	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/doctor"
	"umbrel-tunnel/internal/edge"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/httpapi"
	"umbrel-tunnel/internal/pair"
	"umbrel-tunnel/internal/service"
	"umbrel-tunnel/internal/state"
	"umbrel-tunnel/internal/update"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(ctx, os.Args[2:])
	case "init":
		err = cmdInit(ctx, os.Args[2:])
	case "pair":
		err = cmdPair(ctx, os.Args[2:])
	case "peer":
		err = cmdPeer(ctx, os.Args[2:])
	case "forward":
		err = cmdForwardAPI(ctx, os.Args[2:])
	case "status":
		err = cmdStatus(ctx)
	case "certificates":
		var data []byte
		method, path := "GET", "/api/certificates"
		if len(os.Args) == 3 && os.Args[2] == "retry" {
			method, path = "POST", path+"/retry"
		} else if len(os.Args) != 2 {
			err = fmt.Errorf("uso: certificates [retry]")
			break
		}
		data, err = apiRequest(ctx, method, path, nil)
		if err == nil {
			fmt.Print(string(data))
		}
	case "token":
		err = cmdToken(os.Args[2:])
	case "doctor":
		err = cmdDoctor(ctx, os.Args[2:])
	case "update":
		err = cmdUpdate(ctx, os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "uninstall":
		err = cmdUninstall(ctx, os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `umbrel-tunnel - plano de control del VPS

Uso:
  umbrel-tunnel <comando> [opciones]

Comandos:
  serve                         arranca la API (lo usa systemd)
  init                          crea configuración, claves y token del servidor
  pair                          imprime el código de emparejamiento
  peer list|add|rm|config       gestiona peers
  forward list|show|check|add|edit|rm|enable|disable|reconcile
                                 gestiona puertos públicos
  status                        estado del VPS (JSON)
  certificates [retry]          estado/caducidad o reintento de emisión (JSON)
  token show|rotate             muestra o rota el token
  doctor                        diagnóstico del sistema
  update [--from URL|PATH]      actualiza binario y unidades (por defecto, la última release)
  backup|restore                copia de seguridad de configuración y estado
  uninstall [--purge]           desinstala
  version                       muestra la versión
`)
}

func paths() config.Paths  { return config.DefaultPaths() }
func runner() execx.Runner { return execx.Real{} }

func cmdServe(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", "", "dirección de escucha (override, solo pruebas)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := service.Open(paths(), runner())
	if err != nil {
		return fmt.Errorf("%w (ejecuta `umbrel-tunnel init`)", err)
	}
	if *listen != "" {
		svc.Cfg.APIListen = *listen
	}
	svc.Edge = edge.New(svc.Paths.State)
	svc.Edge.SetPublicHost(svc.Cfg.Endpoint)
	defer svc.Edge.Close()

	if err := svc.Reconcile(ctx); err != nil {
		log.Printf("reconcile: %v", err)
	}

	api := httpapi.New(svc, version, runner())
	srv := &http.Server{
		Addr:              svc.Cfg.APIListen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("umbrel-tunnel %s escuchando en %s", version, svc.Cfg.APIListen)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func cmdInit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	endpoint := fs.String("endpoint", "", "IP pública fija del VPS (se detecta si se omite)")
	token := fs.String("token", "", "token de API (se genera si se omite)")
	apiListen := fs.String("api-listen", "", "dirección de la API (por defecto 10.0.0.1:8080)")
	apiPort := fs.Int("api-port", 0, "puerto de la API")
	subnet := fs.String("subnet", "", "subred del túnel")
	serverIP := fs.String("server-ip", "", "IP del servidor en el túnel")
	umbrelIP := fs.String("umbrel-ip", "", "IP del peer de Umbrel")
	umbrelPub := fs.String("umbrel-pubkey", "", "clave pública de Umbrel (modo manual)")
	wgPort := fs.Int("wg-port", 0, "puerto UDP de WireGuard")
	mtu := fs.Int("mtu", 0, "MTU del túnel")
	publicAPI := fs.Bool("public-api", false, "expone la API fuera del túnel")
	force := fs.Bool("force", false, "sobrescribe la configuración existente")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, p, err := service.Initialize(ctx, paths(), runner(), service.InitOptions{
		Endpoint:     *endpoint,
		Token:        *token,
		APIListen:    *apiListen,
		APIPort:      *apiPort,
		Subnet:       *subnet,
		ServerIP:     *serverIP,
		UmbrelIP:     *umbrelIP,
		UmbrelPubKey: *umbrelPub,
		WGPort:       *wgPort,
		MTU:          *mtu,
		PublicAPI:    *publicAPI,
		Force:        *force,
	})
	if err != nil {
		return err
	}

	fmt.Printf("Configuración: %s\n", svc.Paths.ConfigFile())
	fmt.Printf("Endpoint:      %s\n", svc.Cfg.Endpoint)
	fmt.Printf("API:           %s\n", svc.APIURL())
	printPairing(p)
	return nil
}

func printPairing(p pair.Pairing) {
	fmt.Print("\n" + pair.Block(p))
	fmt.Println("\nLa app de Umbrel genera su propia clave WireGuard y registra la")
	fmt.Println("clave pública a través de la API del túnel. No hay secretos de")
	fmt.Println("WireGuard en el código de emparejamiento.")
}

func cmdPair(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("pair", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "salida JSON")
	rotate := fs.Bool("rotate-token", false, "rota el token antes de imprimir")
	if err := fs.Parse(args); err != nil {
		return err
	}

	svc, err := service.Open(paths(), runner())
	if err != nil {
		return err
	}

	if *rotate {
		token, err := config.GenerateToken()
		if err != nil {
			return err
		}
		if err := svc.Paths.SaveToken(token); err != nil {
			return err
		}
	}

	p, err := svc.Pairing()
	if err != nil {
		return err
	}
	if *asJSON {
		data, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	}
	printPairing(p)
	return nil
}

func cmdPeer(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("uso: umbrel-tunnel peer list|add|rm|config")
	}
	svc, err := service.Open(paths(), runner())
	if err != nil {
		return err
	}

	switch args[0] {
	case "list":
		data, err := apiRequest(ctx, "GET", "/api/peers", nil)
		if err != nil {
			return err
		}
		var peers []state.Peer
		if err := json.Unmarshal(data, &peers); err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tNOMBRE\tIP\tCLAVE PÚBLICA")
		for _, p := range peers {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.ID, p.Name, p.AllowedIP, p.PublicKey)
		}
		return w.Flush()

	case "add":
		fs := flag.NewFlagSet("peer add", flag.ExitOnError)
		name := fs.String("name", "", "nombre del peer")
		ip := fs.String("ip", "", "IP dentro del túnel")
		pub := fs.String("pubkey", "", "clave pública (se genera si se omite)")
		endpoint := fs.String("endpoint", "", "endpoint conocido (opcional)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *name == "" {
			return fmt.Errorf("falta --name")
		}
		if err := svc.ValidateIPInSubnet(*ip); err != nil {
			return err
		}
		privateKey := ""
		publicKey := strings.TrimSpace(*pub)
		if publicKey == "" {
			privateKey, err = svc.WG.GenKey(ctx)
			if err != nil {
				return err
			}
			publicKey, err = svc.WG.PubKey(ctx, privateKey)
			if err != nil {
				return err
			}
		} else if !service.ValidPubKey(publicKey) {
			return fmt.Errorf("clave pública inválida")
		}
		_, err := apiRequest(ctx, "POST", "/api/peers", map[string]string{
			"name": *name, "public_key": publicKey, "allowed_ip": *ip, "endpoint": *endpoint,
		})
		if err != nil {
			return err
		}
		fmt.Printf("Peer %s (%s) creado.\n", *name, *ip)
		if privateKey != "" {
			fmt.Printf("Clave privada (guárdala, no se vuelve a mostrar): %s\n", privateKey)
		}
		return nil

	case "rm":
		if len(args) < 2 {
			return fmt.Errorf("uso: umbrel-tunnel peer rm <id>")
		}
		_, err := apiRequest(ctx, "DELETE", "/api/peers/"+args[1], nil)
		if err != nil {
			return err
		}
		fmt.Printf("Peer %s eliminado.\n", args[1])
		return nil

	case "config":
		if len(args) < 2 {
			return fmt.Errorf("uso: umbrel-tunnel peer config <id>")
		}
		peer, ok := svc.Store.PeerByID(args[1])
		if !ok {
			return fmt.Errorf("peer %s no encontrado", args[1])
		}
		clientKey, err := svc.ClientPrivateKey()
		if err != nil || clientKey == "" {
			return fmt.Errorf("no hay clave privada del cliente (modo manual)")
		}
		serverPub, err := svc.ServerPublicKey()
		if err != nil {
			return err
		}
		fmt.Print(svc.WG.ClientConfig(clientKey, serverPub, peer.AllowedIP))
		return nil
	}
	return fmt.Errorf("subcomando desconocido: %s", args[0])
}

func cmdToken(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("uso: umbrel-tunnel token show|rotate")
	}
	p := paths()
	switch args[0] {
	case "show":
		token, err := p.LoadToken()
		if err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	case "rotate":
		token, err := config.GenerateToken()
		if err != nil {
			return err
		}
		if err := p.SaveToken(token); err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	}
	return fmt.Errorf("subcomando desconocido: %s", args[0])
}

func cmdDoctor(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "salida JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	svc, err := service.Open(paths(), runner())
	var report doctor.Report
	if err != nil {
		report = doctor.Report{Version: version, Failed: true, Checks: []doctor.Check{{Name: "config", Status: "fail", Detail: err.Error()}}}
	} else {
		report = doctor.Run(ctx, svc, runner(), version)
	}
	if *asJSON {
		fmt.Println(report.JSON())
	} else {
		report.Print(os.Stdout)
	}
	if report.Failed {
		os.Exit(1)
	}
	return nil
}

func cmdUpdate(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	from := fs.String("from", "", "URL o ruta del nuevo binario (por defecto, la última release)")
	sha := fs.String("sha256", "", "checksum esperado")
	noRestart := fs.Bool("no-restart", false, "no reinicia el servicio")
	noUnits := fs.Bool("no-units", false, "no actualiza las unidades systemd")
	if err := fs.Parse(args); err != nil {
		return err
	}
	res, err := update.Apply(ctx, update.Options{
		Source:  *from,
		SHA256:  *sha,
		Restart: !*noRestart,
		Units:   !*noUnits,
		// systemd waits for the old process and starts the new one; 10s is tight.
		Runner: execx.Real{Timeout: 60 * time.Second},
	})
	if err != nil {
		return err
	}
	fmt.Printf("Binario actualizado: %s\n", res.Path)
	switch {
	case res.From != "" && res.To != "" && res.From != res.To:
		fmt.Printf("Versión: %s → %s\n", res.From, res.To)
	case res.From != "" && res.From == res.To:
		fmt.Printf("Versión: %s (ya era la instalada)\n", res.To)
	case res.To != "":
		fmt.Printf("Versión: %s\n", res.To)
	}
	if !*noUnits {
		fmt.Println("Unidades systemd actualizadas (systemctl daemon-reload).")
	}
	if *noRestart {
		fmt.Println("Reinicia para aplicar el cambio: systemctl restart umbrel-tunnel")
	}
	return nil
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	output := fs.String("output", "", "archivo de salida")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *output == "" {
		*output = "umbrel-tunnel-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := backup.Create(file, paths()); err != nil {
		return err
	}
	abs, _ := filepath.Abs(*output)
	fmt.Printf("Copia creada: %s\n", abs)
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	from := fs.String("from", "", "archivo de entrada")
	force := fs.Bool("force", false, "sobrescribe la instalación actual")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return fmt.Errorf("falta --from")
	}
	file, err := os.Open(*from)
	if err != nil {
		return err
	}
	defer file.Close()
	if err := backup.Restore(file, paths(), *force); err != nil {
		return err
	}
	fmt.Println("Copia restaurada. Reinicia: systemctl restart umbrel-tunnel wg-quick@wg0 umbrel-tunnel-firewall")
	return nil
}

func cmdUninstall(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	purge := fs.Bool("purge", false, "elimina también configuración y estado")
	if err := fs.Parse(args); err != nil {
		return err
	}
	run := runner()

	_, _ = run.Run(ctx, "systemctl", "disable", "--now", "umbrel-tunnel", "umbrel-tunnel-firewall", "wg-quick@wg0")
	_, _ = run.Run(ctx, "nft", "delete", "table", "inet", "umbrel_tunnel")

	for _, path := range []string{
		"/etc/systemd/system/umbrel-tunnel.service",
		"/etc/systemd/system/umbrel-tunnel-firewall.service",
		"/etc/tmpfiles.d/umbrel-tunnel.conf",
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	_, _ = run.Run(ctx, "systemctl", "daemon-reload")

	if data, err := os.ReadFile("/etc/wireguard/wg0.conf"); err == nil && strings.Contains(string(data), "Managed by umbrel-tunnel") {
		_ = os.Remove("/etc/wireguard/wg0.conf")
	}

	if *purge {
		_ = os.RemoveAll("/etc/umbrel-tunnel")
		_ = os.RemoveAll("/var/lib/umbrel-tunnel")
		_ = os.RemoveAll("/run/umbrel-tunnel")
	}

	exe, _ := os.Executable()
	_ = os.Remove(exe)
	fmt.Println("umbrel-tunnel desinstalado.")
	if !*purge {
		fmt.Println("Se conservaron /etc/umbrel-tunnel y /var/lib/umbrel-tunnel (usa --purge para borrarlos).")
	}
	return nil
}
