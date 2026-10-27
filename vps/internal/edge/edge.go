// Package edge terminates public HTTPS and TCP/TLS on the VPS. Only explicitly
// configured names can obtain certificates; the administration API is unrelated.
package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/netutil"
	"umbrel-tunnel/internal/state"
)

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func ValidDomain(domain string) bool {
	if len(domain) > 253 || domain != strings.ToLower(domain) || net.ParseIP(domain) != nil {
		return false
	}
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if !label.MatchString(p) {
			return false
		}
	}
	return true
}

// Validate checks all port reservations, including disabled publications. A
// secure configuration must never silently take over an existing DNAT rule.
func Validate(forwards []state.Forward, apiPort int) error {
	secure := false
	names := map[string]bool{}
	for _, f := range forwards {
		mode := f.AccessMode
		if mode == "" || mode == "direct" {
			continue
		}
		if mode != "https" && mode != "tls" {
			return fmt.Errorf("access_mode debe ser direct, https o tls")
		}
		if f.Protocol != "tcp" || !ValidDomain(f.Domain) {
			return fmt.Errorf("HTTPS/TLS requiere TCP y un dominio público válido en minúsculas")
		}
		if f.PublicPort == 22 || f.PublicPort == apiPort || f.PublicPort == 80 {
			return fmt.Errorf("puerto reservado")
		}
		if mode == "https" && f.PublicPort != 443 {
			return fmt.Errorf("HTTPS usa el puerto público 443")
		}
		if mode == "tls" && f.PublicPort == 443 {
			return fmt.Errorf("443 se reserva para HTTPS; elige otro puerto TLS")
		}
		if names[f.Domain] {
			return fmt.Errorf("el dominio ya tiene una publicación cifrada")
		}
		names[f.Domain] = true
		secure = true
	}
	if secure {
		for _, f := range forwards {
			if (f.AccessMode == "" || f.AccessMode == "direct") && f.Protocol != "udp" && (f.PublicPort == 80 || f.PublicPort == 443) {
				return fmt.Errorf("80/443 ya publicados: retira o cambia esas reglas antes de activar HTTPS/TLS")
			}
		}
		if apiPort == 80 || apiPort == 443 {
			return fmt.Errorf("la API ocupa 80/443")
		}
	}
	return nil
}

type Manager struct {
	mu        sync.RWMutex
	routes    []state.Forward
	listeners map[int]net.Listener
	certs     *autocert.Manager
	errors    map[string]string
	stop      chan struct{}
	wake      chan struct{}
	listen    func(string, string) (net.Listener, error)
}

func New(dir string) *Manager {
	m := &Manager{listeners: map[int]net.Listener{}, errors: map[string]string{}, stop: make(chan struct{}), wake: make(chan struct{}, 1)}
	m.listen = net.Listen
	m.certs = &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(filepath.Join(dir, "certificates")), HostPolicy: m.hostPolicy}
	if os.Getenv("UMBREL_TUNNEL_ACME_STAGING") == "1" {
		m.certs.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
		m.certs.Cache = autocert.DirCache(filepath.Join(dir, "certificates-staging"))
	}
	go m.warmCertificates()
	return m
}

func (m *Manager) hostPolicy(_ context.Context, host string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range m.routes {
		if f.Enabled && f.Domain == host && (f.AccessMode == "https" || f.AccessMode == "tls") {
			return nil
		}
	}
	return fmt.Errorf("dominio no autorizado")
}

// Use one RSA certificate per name for both HTTPS and Electrum clients. Without
// this, autocert may issue a second ECDSA certificate on the first browser visit
// after pre-warming the RSA certificate, doubling issuance and renewal work.
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	copy := *hello
	copy.CipherSuites = nil
	return m.certs.GetCertificate(&copy)
}

// Apply pre-binds every new listener before replacing the active routing table.
func (m *Manager) Apply(routes []state.Forward) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	wanted := map[int]bool{}
	for _, f := range routes {
		if f.Enabled && (f.AccessMode == "https" || f.AccessMode == "tls") {
			wanted[80] = true
			wanted[f.PublicPort] = true
		}
	}
	added := map[int]net.Listener{}
	for port := range wanted {
		if m.listeners[port] != nil {
			continue
		}
		ln, err := m.listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			for _, l := range added {
				l.Close()
			}
			return fmt.Errorf("escuchar puerto %d: %w", port, err)
		}
		added[port] = ln
	}
	m.routes = append([]state.Forward(nil), routes...)
	for port, ln := range added {
		m.listeners[port] = ln
		switch port {
		case 80:
			ln = netutil.LimitListener(ln, 32)
			m.listeners[port] = ln
			srv := &http.Server{Handler: m.certs.HTTPHandler(http.HandlerFunc(m.redirect)), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
			srv.MaxHeaderBytes = 64 << 10
			go srv.Serve(ln)
		case 443:
			ln = netutil.LimitListener(ln, 128)
			m.listeners[port] = ln
			srv := &http.Server{Handler: http.HandlerFunc(m.proxyHTTP), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
			cfg := m.certs.TLSConfig()
			cfg.GetCertificate = m.getCertificate
			cfg.MinVersion = tls.VersionTLS12
			// Serve (rather than ServeTLS) does not configure HTTP/2. Do not
			// advertise h2 without an HTTP/2 server behind the TLS listener.
			cfg.NextProtos = []string{"http/1.1", "acme-tls/1"}
			srv.MaxHeaderBytes = 64 << 10
			go srv.Serve(tls.NewListener(ln, cfg))
		default:
			go m.serveTCP(ln, port)
		}
	}
	for port, ln := range m.listeners {
		if !wanted[port] {
			ln.Close()
			delete(m.listeners, port)
		}
	}
	return nil
}

func (m *Manager) route(host string, port int) (state.Forward, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range m.routes {
		if f.Enabled && (f.AccessMode == "https" || f.AccessMode == "tls") && f.PublicPort == port && f.Domain != "" && (host == "" || f.Domain == host) {
			return f, true
		}
	}
	return state.Forward{}, false
}

func (m *Manager) redirect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if _, ok := m.route(host, 443); !ok {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

func (m *Manager) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	f, ok := m.route(host, 443)
	if !ok || r.TLS == nil || r.TLS.ServerName != host {
		http.Error(w, "dominio no publicado", http.StatusMisdirectedRequest)
		return
	}
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(f.TargetIP, fmt.Sprint(f.TargetPort))}
	p := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		pr.Out.Host = host
		pr.SetXForwarded()
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
		pr.Out.Header.Del("Forwarded")
	}, Transport: transport}
	p.ServeHTTP(w, r)
}

var transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext, ResponseHeaderTimeout: 30 * time.Second, IdleConnTimeout: 90 * time.Second, MaxIdleConns: 32}

func (m *Manager) serveTCP(ln net.Listener, port int) {
	// Limit active TLS streams to protect the small VPS from unbounded goroutines.
	sem := make(chan struct{}, 128)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		default:
			c.Close()
			continue
		}
		go func() {
			defer func() { <-sem; c.Close() }()
			f, ok := m.route("", port)
			if !ok {
				return
			}
			cfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				if hello.ServerName != "" && hello.ServerName != f.Domain {
					return nil, fmt.Errorf("SNI no coincide")
				}
				copy := *hello
				copy.ServerName = f.Domain
				return m.getCertificate(&copy)
			}}
			client := tls.Server(c, cfg)
			c.SetDeadline(time.Now().Add(30 * time.Second))
			if err := client.Handshake(); err != nil {
				return
			}
			c.SetDeadline(time.Time{})
			backend, err := net.DialTimeout("tcp", net.JoinHostPort(f.TargetIP, fmt.Sprint(f.TargetPort)), 10*time.Second)
			if err != nil {
				return
			}
			defer backend.Close()
			// Close both sides when either stream ends; no lingering copy goroutines.
			done := make(chan struct{})
			go func() { io.Copy(backend, client); backend.Close(); client.Close(); close(done) }()
			io.Copy(client, backend)
			client.Close()
			backend.Close()
			<-done
		}()
	}
}

func (m *Manager) warmCertificates() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	last := map[string]time.Time{}
	for {
		// Keep automatic failed-validation retries below common CA rate limits.
		interval := 30 * time.Minute
		select {
		case <-m.stop:
			return
		case <-ticker.C:
		case <-m.wake:
			interval = time.Minute
		}
		m.mu.RLock()
		routes := append([]state.Forward(nil), m.routes...)
		m.mu.RUnlock()
		for _, f := range routes {
			if !f.Enabled || (f.AccessMode != "https" && f.AccessMode != "tls") || time.Since(last[f.Domain]) < interval {
				continue
			}
			last[f.Domain] = time.Now()
			_, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: f.Domain})
			m.mu.Lock()
			if err != nil {
				m.errors[f.Domain] = err.Error()
				log.Printf("certificado %s: %v", f.Domain, err)
			} else {
				delete(m.errors, f.Domain)
			}
			m.mu.Unlock()
		}
	}
}

// Retry schedules work in the single background worker, with a per-name
// cooldown. Never delete a working certificate to force a renewal.
func (m *Manager) Retry() {
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

// Status reads only public certificate metadata, never private keys.
func (m *Manager) Status() []map[string]any {
	m.mu.RLock()
	routes := append([]state.Forward(nil), m.routes...)
	errs := map[string]string{}
	for k, v := range m.errors {
		errs[k] = v
	}
	m.mu.RUnlock()
	out := []map[string]any{}
	for _, f := range routes {
		if f.Domain == "" || (f.AccessMode != "https" && f.AccessMode != "tls") {
			continue
		}
		item := map[string]any{"domain": f.Domain, "enabled": f.Enabled, "state": "pending", "error": errs[f.Domain]}
		for _, key := range []string{f.Domain, f.Domain + "+rsa"} {
			data, err := m.certs.Cache.Get(context.Background(), key)
			if err != nil {
				continue
			}
			for len(data) > 0 {
				block, rest := pem.Decode(data)
				if block == nil {
					break
				}
				data = rest
				if block.Type != "CERTIFICATE" {
					continue
				}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					continue
				}
				item["not_after"] = cert.NotAfter
				item["state"] = "ready"
				if time.Until(cert.NotAfter) < 14*24*time.Hour {
					item["state"] = "expiring"
				}
				if time.Now().After(cert.NotAfter) {
					item["state"] = "expired"
				}
				break
			}
		}
		out = append(out, item)
	}
	return out
}

func (m *Manager) Close() {
	close(m.stop)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ln := range m.listeners {
		ln.Close()
	}
}
