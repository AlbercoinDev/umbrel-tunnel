package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/state"
)

// All online forward commands use the daemon's single state owner. Opening a
// separate Store here would race its in-memory state and lose updates.
func apiRequest(ctx context.Context, method, path string, body any) ([]byte, error) {
	cfg, err := config.Load(paths())
	if err != nil {
		return nil, err
	}
	token, err := paths().LoadToken()
	if err != nil {
		return nil, err
	}
	host, port, err := cfg.ParseAPIHostPort()
	if err != nil {
		return nil, err
	}
	if host == "0.0.0.0" || host == "" {
		host = "127.0.0.1"
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+net.JoinHostPort(host, strconv.Itoa(port))+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API local no disponible; arranca umbrel-tunnel.service: %w", err)
	}
	defer res.Body.Close()
	result, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(result)))
	}
	return result, nil
}

func cmdStatus(ctx context.Context) error {
	data, err := apiRequest(ctx, "GET", "/api/status", nil)
	if err == nil {
		fmt.Print(string(data))
	}
	return err
}

func cmdForwardAPI(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("uso: forward list|show|check|add|edit|rm|enable|disable|reconcile")
	}
	command := args[0]
	rest := args[1:]
	var id string
	if command == "show" || command == "check" || command == "edit" || command == "rm" || command == "enable" || command == "disable" {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			return fmt.Errorf("falta el ID de la publicación")
		}
		id, rest = rest[0], rest[1:]
	}
	fs := flag.NewFlagSet("forward "+command, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "salida JSON")
	name := fs.String("name", "", "nombre")
	port := fs.Int("public-port", 0, "puerto público")
	target := fs.String("target-ip", "", "IP del peer")
	targetPort := fs.Int("target-port", 0, "puerto destino")
	protocol := fs.String("protocol", "tcp", "tcp o udp")
	disabled := fs.Bool("disabled", false, "crear desactivado")
	mode := fs.String("access-mode", "direct", "direct, https o tls")
	domain := fs.String("domain", "", "dominio público completo")
	terms := fs.Bool("accept-acme-terms", false, "aceptar condiciones de Let's Encrypt y emisión pública")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("argumentos inesperados: %v", fs.Args())
	}
	method, path := "GET", "/api/forwards"
	var body any
	switch command {
	case "list", "show":
	case "check":
		path += "/" + url.PathEscape(id) + "/check"
	case "add":
		method = "POST"
		body = map[string]any{"name": *name, "public_port": *port, "target_ip": *target, "target_port": *targetPort, "protocol": *protocol, "enabled": !*disabled, "managed_by": "vps", "access_mode": *mode, "domain": *domain, "accept_acme_terms": *terms}
	case "edit":
		patch := map[string]any{}
		values := map[string]any{"name": *name, "public-port": *port, "target-ip": *target, "target-port": *targetPort, "protocol": *protocol, "access-mode": *mode, "domain": *domain, "accept-acme-terms": *terms}
		fs.Visit(func(f *flag.Flag) {
			if value, ok := values[f.Name]; ok {
				patch[strings.ReplaceAll(f.Name, "-", "_")] = value
			}
		})
		if len(patch) == 0 {
			return fmt.Errorf("indica al menos un campo que modificar")
		}
		method, path, body = "PATCH", path+"/"+url.PathEscape(id), patch
	case "enable", "disable":
		method, path, body = "PATCH", path+"/"+url.PathEscape(id), map[string]bool{"enabled": command == "enable"}
	case "rm":
		method, path = "DELETE", path+"/"+url.PathEscape(id)
	case "reconcile":
		method, path = "POST", "/api/forwards/reconcile"
	default:
		return fmt.Errorf("subcomando desconocido: %s", command)
	}
	data, err := apiRequest(ctx, method, path, body)
	if err != nil {
		return err
	}
	if command == "show" || command == "list" {
		var forwards []state.Forward
		if err := json.Unmarshal(data, &forwards); err != nil {
			return err
		}
		if command == "show" {
			for _, f := range forwards {
				if f.ID == id {
					return json.NewEncoder(os.Stdout).Encode(f)
				}
			}
			return fmt.Errorf("publicación no encontrada: %s", id)
		}
		if !*asJSON {
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tNOMBRE\tPÚBLICO\tDESTINO\tPROTO\tACTIVO\tMODO\tDOMINIO")
			for _, f := range forwards {
				mode := f.AccessMode
				if mode == "" {
					mode = "direct"
				}
				fmt.Fprintf(w, "%s\t%s\t%d\t%s:%d\t%s\t%v\t%s\t%s\n", f.ID, f.Name, f.PublicPort, f.TargetIP, f.TargetPort, f.Protocol, f.Enabled, mode, f.Domain)
			}
			return w.Flush()
		}
	}
	fmt.Print(string(data))
	return nil
}
