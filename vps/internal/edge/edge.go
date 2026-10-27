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
	"strconv"
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
			if f.Domain != "" && !ValidDomain(f.Domain) {
				return fmt.Errorf("dominio público inválido")
			}
			continue
		}
		if mode != "http" && mode != "https" && mode != "tls" {
			return fmt.Errorf("access_mode debe ser direct, http, https o tls")
		}
		if f.Protocol != "tcp" || !ValidDomain(f.Domain) {
			return fmt.Errorf("HTTP/HTTPS/TLS requiere TCP y un dominio público válido en minúsculas")
		}
		if f.PublicPort == 22 || f.PublicPort == apiPort || (f.PublicPort == 80 && mode != "http") {
			return fmt.Errorf("puerto reservado")
		}
		if mode == "https" && f.PublicPort != 443 {
			return fmt.Errorf("HTTPS usa el puerto público 443")
		}
		if (mode == "tls" || mode == "http") && f.PublicPort == 443 {
			return fmt.Errorf("443 se reserva para HTTPS; elige otro puerto TLS")
		}
		key := fmt.Sprintf("%s:%d", f.Domain, f.PublicPort)
		if names[key] {
			return fmt.Errorf("el dominio ya tiene una publicación cifrada")
		}
		names[key] = true
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

type certFailure struct {
	Err       string
	Hint      string
	CheckedAt time.Time
}

type Manager struct {
	mu         sync.RWMutex
	routes     []state.Forward
	listeners  map[int]net.Listener
	certs      *autocert.Manager
	errors     map[string]certFailure
	stop       chan struct{}
	retry      chan struct{}
	listen     func(string, string) (net.Listener, error)
	lookup     func(context.Context, string) ([]string, error)
	issue      func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	publicHost string
	probe      func(context.Context, string, int) error
}

func New(dir string) *Manager {
	m := &Manager{listeners: map[int]net.Listener{}, errors: map[string]certFailure{}, stop: make(chan struct{}), retry: make(chan struct{}, 1)}
	m.listen = net.Listen
	m.lookup = net.DefaultResolver.LookupHost
	m.probe = probePort
	m.certs = &autocert.Manager{Prompt: autocert.AcceptTOS, Cache: autocert.DirCache(filepath.Join(dir, "certificates")), HostPolicy: m.hostPolicy}
	if os.Getenv("UMBREL_TUNNEL_ACME_STAGING") == "1" {
		m.certs.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
		m.certs.Cache = autocert.DirCache(filepath.Join(dir, "certificates-staging"))
	}
	m.issue = m.getCertificate
	go m.warmCertificates()
	return m
}

// SetPublicHost enables the post-failure port diagnosis. It must be the public
// IPv4/host clients use, not a tunnel address.
func (m *Manager) SetPublicHost(host string) {
	m.mu.Lock()
	m.publicHost = strings.TrimSpace(host)
	m.mu.Unlock()
}

func probePort(ctx context.Context, host string, port int) error {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return err
	}
	return conn.Close()
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
		if f.Enabled && f.AccessMode == "http" {
			wanted[f.PublicPort] = true
		}
		if f.Enabled && (f.AccessMode == "https" || f.AccessMode == "tls") {
			wanted[80] = true
			wanted[f.PublicPort] = true
		}
	}
	added := map[int]net.Listener{}
	for port := range wanted {
		if m.listeners[port] == nil || port == 80 || port == 443 {
			continue
		}
		oldHTTP, newHTTP := false, false
		for _, f := range m.routes {
			if f.Enabled && f.PublicPort == port && f.AccessMode == "http" {
				oldHTTP = true
			}
		}
		for _, f := range routes {
			if f.Enabled && f.PublicPort == port && f.AccessMode == "http" {
				newHTTP = true
			}
		}
		if oldHTTP != newHTTP {
			return fmt.Errorf("pausa la publicación antes de cambiar HTTP/TLS en el mismo puerto / pause before changing HTTP/TLS on the same port")
		}
	}
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
			isHTTP := false
			for _, f := range routes {
				if f.Enabled && f.PublicPort == port && f.AccessMode == "http" {
					isHTTP = true
				}
			}
			if isHTTP {
				ln = netutil.LimitListener(ln, 128)
				m.listeners[port] = ln
				p := port
				srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { m.proxyRequest(w, r, p) }), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
				go srv.Serve(ln)
			} else {
				go m.serveTCP(ln, port)
			}
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
		if f.Enabled && (f.AccessMode == "http" || f.AccessMode == "https" || f.AccessMode == "tls") && f.PublicPort == port && f.Domain != "" && (host == "" || f.Domain == host) {
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
	if f, ok := m.route(host, 80); ok && f.AccessMode == "http" {
		m.proxyRequest(w, r, 80)
		return
	}
	if _, ok := m.route(host, 443); !ok {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
}

func (m *Manager) proxyHTTP(w http.ResponseWriter, r *http.Request) {
	m.proxyRequest(w, r, 443)
}

func (m *Manager) proxyRequest(w http.ResponseWriter, r *http.Request, port int) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	f, ok := m.route(host, port)
	if !ok || (port == 443 && (r.TLS == nil || r.TLS.ServerName != host)) {
		http.Error(w, "dominio no publicado", http.StatusMisdirectedRequest)
		return
	}
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(f.TargetIP, fmt.Sprint(f.TargetPort))}
	p := &httputil.ReverseProxy{Rewrite: func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		pr.Out.Host = host
		pr.SetXForwarded()
		if port == 443 {
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		} else {
			pr.Out.Header.Set("X-Forwarded-Proto", "http")
		}
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
		forced := false
		select {
		case <-m.stop:
			return
		case <-m.retry:
			forced = true
		case <-ticker.C:
		}
		m.warmOnce(last, interval, forced)
	}
}

// warmOnce checks names that are due, or every TLS name when the user requests
// an immediate retry. DNS is checked first so an unresolvable name does not
// produce a misleading ACME error or consume CA rate limits.
func (m *Manager) warmOnce(last map[string]time.Time, interval time.Duration, forced bool) {
	m.mu.RLock()
	routes := append([]state.Forward(nil), m.routes...)
	m.mu.RUnlock()
	seen := map[string]bool{}
	for _, f := range routes {
		if !f.Enabled || (f.AccessMode != "https" && f.AccessMode != "tls") || seen[f.Domain] {
			continue
		}
		seen[f.Domain] = true
		if !forced && time.Since(last[f.Domain]) < interval {
			continue
		}
		last[f.Domain] = time.Now()
		if err := m.portsReady(f); err != nil {
			m.recordError(f.Domain, err)
			log.Printf("certificado %s: %v", f.Domain, err)
			continue
		}
		if err := m.checkDNS(f.Domain); err != nil {
			m.recordError(f.Domain, err)
			log.Printf("certificado %s: %v", f.Domain, err)
			continue
		}
		if _, err := m.issue(&tls.ClientHelloInfo{ServerName: f.Domain}); err != nil {
			m.recordIssueError(f.Domain, err)
			log.Printf("certificado %s: %v", f.Domain, err)
		} else {
			m.clearError(f.Domain)
		}
	}
}

// portsReady verifies that the edge itself owns the ports the CA will use. A
// missing listener means the unit cannot bind (usually an old unit without
// CAP_NET_BIND_SERVICE) or another process holds the port, so ACME is skipped.
func (m *Manager) portsReady(f state.Forward) error {
	needed := []int{80}
	if f.AccessMode == "https" {
		needed = append(needed, 443)
	} else {
		needed = append(needed, f.PublicPort)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, port := range needed {
		if m.listeners[port] == nil {
			return fmt.Errorf("Puerto: el VPS no escucha en TCP %d (revisa CAP_NET_BIND_SERVICE y el firewall local)", port)
		}
	}
	return nil
}

func (m *Manager) checkDNS(domain string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := m.lookup(ctx, domain)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("DNS: tiempo de espera resolviendo %s", domain)
		}
		return fmt.Errorf("DNS: %s no resuelve (%v)", domain, err)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("DNS: %s no tiene direcciones A/AAAA", domain)
	}
	return nil
}

func (m *Manager) recordError(domain string, err error) {
	m.mu.Lock()
	m.errors[domain] = certFailure{Err: err.Error(), Hint: certHint(err), CheckedAt: time.Now().UTC()}
	m.mu.Unlock()
}

// recordIssueError adds a reachability hint when ACME failed for a name that is
// supposed to be public. DNS and rate-limit causes keep their own guidance.
func (m *Manager) recordIssueError(domain string, err error) {
	hint := certHint(err)
	if explainReach(err) {
		if problem := m.reachProblem(); problem != "" {
			hint = problem
		}
	}
	m.mu.Lock()
	m.errors[domain] = certFailure{Err: err.Error(), Hint: hint, CheckedAt: time.Now().UTC()}
	m.mu.Unlock()
}

func explainReach(err error) bool {
	msg := err.Error()
	return !strings.HasPrefix(msg, "DNS:") &&
		!strings.Contains(msg, "rateLimited") &&
		!strings.Contains(msg, "too many failed authorizations")
}

// reachProblem probes the public ports from the VPS itself. A provider firewall
// can still hide behind local delivery, so it is only used as a hint; the app
// adds a real external check from the Umbrel network.
func (m *Manager) reachProblem() string {
	m.mu.RLock()
	host := m.publicHost
	need443 := false
	for _, f := range m.routes {
		if f.Enabled && f.AccessMode == "https" {
			need443 = true
		}
	}
	probe := m.probe
	m.mu.RUnlock()
	if host == "" || probe == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	err80 := probe(ctx, host, 80)
	var err443 error
	if need443 {
		err443 = probe(ctx, host, 443)
	}
	switch {
	case err80 != nil && err443 != nil:
		return fmt.Sprintf("TCP 80 y 443 no responden en %s desde el propio VPS; revisa el firewall del proveedor.", host)
	case err80 != nil:
		return fmt.Sprintf("TCP 80 no responde en %s desde el propio VPS; HTTP-01 y sus renovaciones fallarán. Revisa el firewall del proveedor.", host)
	case err443 != nil:
		return fmt.Sprintf("TCP 443 no responde en %s desde el propio VPS; TLS-ALPN-01 fallará. Revisa el firewall del proveedor.", host)
	}
	return ""
}

func (m *Manager) clearError(domain string) {
	m.mu.Lock()
	delete(m.errors, domain)
	m.mu.Unlock()
}

func certHint(err error) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "DNS:"):
		return "Crea un registro A o wildcard hacia el VPS en Solo DNS; no publiques AAAA incorrectos."
	case strings.HasPrefix(msg, "Puerto:"):
		return "Reejecuta el instalador para actualizar la unidad systemd (CAP_NET_BIND_SERVICE) y comprueba qué proceso ocupa el puerto."
	case strings.Contains(msg, "no viable challenge type found"):
		return "Fallaron HTTP-01 y TLS-ALPN-01. Comprueba el DNS (Solo DNS) y que TCP 80 y 443 llegan al VPS."
	case strings.Contains(msg, "rateLimited") || strings.Contains(msg, "too many failed authorizations"):
		return "Let's Encrypt ha limitado los intentos. Espera antes de volver a reintentar."
	default:
		return "Revisa DNS, TCP 80/443 y los logs del VPS antes de reintentar."
	}
}

// Retry schedules an immediate check in the single background worker, bypassing
// the per-name cooldown. Never delete a working certificate to force renewal.
func (m *Manager) Retry() {
	select {
	case m.retry <- struct{}{}:
	default:
	}
}

// Status reads only public certificate metadata, never private keys.
func (m *Manager) Status() []map[string]any {
	m.mu.RLock()
	routes := append([]state.Forward(nil), m.routes...)
	errs := map[string]certFailure{}
	for k, v := range m.errors {
		errs[k] = v
	}
	m.mu.RUnlock()
	out := []map[string]any{}
	byDomain := map[string]map[string]any{}
	for _, f := range routes {
		if f.Domain == "" || (f.AccessMode != "https" && f.AccessMode != "tls") {
			continue
		}
		if previous, ok := byDomain[f.Domain]; ok {
			if f.Enabled {
				previous["enabled"] = true
			}
			continue
		}
		failure, failed := errs[f.Domain]
		item := map[string]any{"domain": f.Domain, "enabled": f.Enabled, "state": "pending"}
		if failed {
			item["checked_at"] = failure.CheckedAt
		}
		byDomain[f.Domain] = item
		certState := ""
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
				certState = "ready"
				if time.Until(cert.NotAfter) < 14*24*time.Hour {
					certState = "expiring"
				}
				if time.Now().After(cert.NotAfter) {
					certState = "expired"
				}
				break
			}
		}
		if certState != "" {
			item["state"] = certState
			if failed {
				item["renewal_error"] = failure.Err
				item["renewal_hint"] = failure.Hint
			}
		} else if failed {
			item["state"] = "error"
			item["error"] = failure.Err
			item["hint"] = failure.Hint
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
