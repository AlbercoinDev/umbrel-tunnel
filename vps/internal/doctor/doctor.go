// Package doctor checks the health of a umbrel-tunnel installation.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/service"
	"umbrel-tunnel/internal/state"
)

// Check is a single diagnostic result.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok, warn, fail
	Detail string `json:"detail,omitempty"`
}

// Report is the result of a doctor run.
type Report struct {
	Version string  `json:"version"`
	Checks  []Check `json:"checks"`
	Failed  bool    `json:"failed"`
}

func (r *Report) add(name, status, detail string) {
	if status == "fail" {
		r.Failed = true
	}
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

// Run performs the checks.
func Run(ctx context.Context, svc *service.Service, run execx.Runner, version string) Report {
	r := Report{Version: version}

	if os.Geteuid() == 0 {
		r.add("root", "ok", "")
	} else {
		r.add("root", "warn", "ejecutando sin privilegios")
	}

	if svc == nil {
		r.add("config", "fail", "no se pudo cargar la configuración")
		return r
	}
	r.add("config", "ok", svc.Cfg.APIListen)

	if info, err := os.Stat(svc.Paths.TokenFile()); err != nil {
		r.add("token", "fail", "no existe")
	} else if info.Mode().Perm()&0o077 != 0 {
		r.add("token", "warn", fmt.Sprintf("permisos %o (debería ser 600)", info.Mode().Perm()))
	} else {
		r.add("token", "ok", "0600")
	}

	if _, err := svc.ServerPrivateKey(); err != nil {
		r.add("clave servidor", "fail", err.Error())
	} else {
		r.add("clave servidor", "ok", "")
	}
	// The Umbrel app normally owns the client private key, so the VPS only
	// needs the peer's public key. A local client key exists only for peers
	// created by the VPS itself.
	if _, err := svc.ClientPrivateKey(); err == nil {
		r.add("clave cliente", "ok", "gestionada por el VPS")
	} else if _, ok := svc.Store.PeerByIP(svc.Cfg.UmbrelIP); ok {
		r.add("clave cliente", "ok", "la clave pública la registra la app de Umbrel")
	} else {
		r.add("clave cliente", "warn", "ningún peer de Umbrel registrado todavía")
	}

	if _, err := os.Stat(svc.Paths.WGConfFile()); err != nil {
		r.add("wg0.conf", "fail", "no existe")
	} else {
		r.add("wg0.conf", "ok", svc.Paths.WGConfFile())
	}

	if _, err := run.Run(ctx, "wg", "show", svc.Cfg.Interface); err != nil {
		r.add("interfaz", "fail", fmt.Sprintf("%s no está arriba", svc.Cfg.Interface))
	} else {
		r.add("interfaz", "ok", svc.Cfg.Interface)
	}

	if _, err := run.Run(ctx, "nft", "list", "table", "inet", "umbrel_tunnel"); err != nil {
		r.add("nftables", "fail", "tabla inet umbrel_tunnel ausente")
	} else {
		r.add("nftables", "ok", "inet umbrel_tunnel")
	}

	if data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		if strings.TrimSpace(string(data)) == "1" {
			r.add("ip_forward", "ok", "1")
		} else {
			r.add("ip_forward", "fail", "0")
		}
	} else {
		r.add("ip_forward", "warn", "no se pudo leer")
	}

	if len(svc.Store.Peers()) == 0 {
		r.add("peers", "fail", "no hay peers")
	} else {
		r.add("peers", "ok", fmt.Sprintf("%d", len(svc.Store.Peers())))
	}

	if out, err := run.Run(ctx, "systemctl", "is-active", "umbrel-tunnel"); err != nil {
		r.add("servicio", "warn", strings.TrimSpace(string(out)))
	} else {
		r.add("servicio", "ok", strings.TrimSpace(string(out)))
	}

	r.add("binario", "ok", version)

	if out, err := run.Run(ctx, "systemctl", "cat", "umbrel-tunnel"); err != nil {
		r.add("unidad", "warn", "no se pudo leer la unidad")
	} else if !hasBindCapability(out) {
		r.add("unidad", "warn", "sin CAP_NET_BIND_SERVICE; reejecuta el instalador para escuchar en 80/443")
	} else {
		r.add("unidad", "ok", "CAP_NET_BIND_SERVICE")
	}

	required := requiredPorts(svc.Store.Forwards())
	if len(required) == 0 {
		r.add("puertos", "ok", "sin publicaciones web/TLS")
	} else {
		var missing []string
		for _, port := range required {
			if !portBound(ctx, run, port) {
				missing = append(missing, fmt.Sprintf("%d", port))
			}
		}
		if len(missing) > 0 {
			r.add("puertos", "fail", "no escuchan: "+strings.Join(missing, ", "))
		} else {
			r.add("puertos", "ok", portList(required))
		}
	}

	// A hairpin failure is possible on some cloud NATs, so this is advisory.
	if svc.Cfg.Endpoint != "" && len(required) > 0 {
		var blocked []string
		for _, port := range required {
			if publicProbe(ctx, svc.Cfg.Endpoint, port) != nil {
				blocked = append(blocked, fmt.Sprintf("%d", port))
			}
		}
		if len(blocked) > 0 {
			r.add("red", "warn", svc.Cfg.Endpoint+": sin respuesta en TCP "+strings.Join(blocked, ", ")+"; revisa el firewall del proveedor")
		} else {
			r.add("red", "ok", svc.Cfg.Endpoint)
		}
	}

	if out, err := run.Run(ctx, "systemctl", "is-active", "wg-quick@"+svc.Cfg.Interface); err != nil {
		r.add("wg-quick", "warn", strings.TrimSpace(string(out)))
	} else {
		r.add("wg-quick", "ok", strings.TrimSpace(string(out)))
	}

	if err := health(ctx, svc); err != nil {
		r.add("api", "warn", err.Error())
	} else {
		r.add("api", "ok", "200")
	}

	return r
}

func health(ctx context.Context, svc *service.Service) error {
	_, port, err := svc.Cfg.ParseAPIHostPort()
	if err != nil {
		return err
	}
	url := "http://" + net.JoinHostPort(svc.Cfg.ServerIP, fmt.Sprintf("%d", port)) + "/health"
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("no responde en %s", url)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d en %s", resp.StatusCode, url)
	}
	return nil
}

// Print writes a human-readable report.
func (r Report) Print(w io.Writer) {
	for _, c := range r.Checks {
		mark := "OK  "
		switch c.Status {
		case "warn":
			mark = "WARN"
		case "fail":
			mark = "FAIL"
		}
		if c.Detail != "" {
			fmt.Fprintf(w, "[%s] %-16s %s\n", mark, c.Name, c.Detail)
		} else {
			fmt.Fprintf(w, "[%s] %s\n", mark, c.Name)
		}
	}
}

// JSON renders the report as JSON.
func (r Report) JSON() string {
	data, _ := json.MarshalIndent(r, "", "  ")
	return string(data)
}

// publicProbe is a seam for tests: a TCP dial to the VPS public address.
var publicProbe = func(ctx context.Context, host string, port int) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
}

func hasBindCapability(unit []byte) bool {
	return strings.Contains(string(unit), "CAP_NET_BIND_SERVICE")
}

// requiredPorts lists the public TCP ports the edge must own, sorted.
func requiredPorts(forwards []state.Forward) []int {
	seen := map[int]bool{}
	for _, f := range forwards {
		if !f.Enabled {
			continue
		}
		switch f.AccessMode {
		case "http":
			seen[f.PublicPort] = true
		case "https", "tls":
			seen[80] = true
			seen[f.PublicPort] = true
		}
	}
	ports := make([]int, 0, len(seen))
	for port := range seen {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func portList(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, fmt.Sprintf("%d", port))
	}
	return strings.Join(parts, ", ")
}

func portBound(ctx context.Context, run execx.Runner, port int) bool {
	out, err := run.Run(ctx, "ss", "-H", "-ltn", fmt.Sprintf("sport = :%d", port))
	return err == nil && strings.TrimSpace(string(out)) != ""
}
