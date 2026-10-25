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
	"strings"
	"time"

	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/service"
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
	if _, err := svc.ClientPrivateKey(); err != nil {
		r.add("clave cliente", "warn", "no existe (modo manual)")
	} else {
		r.add("clave cliente", "ok", "")
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
