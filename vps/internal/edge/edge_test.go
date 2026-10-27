package edge

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"umbrel-tunnel/internal/state"
)

func secure(domain, mode string, port int) state.Forward {
	return state.Forward{Domain: domain, AccessMode: mode, PublicPort: port, Protocol: "tcp", TargetIP: "127.0.0.1", TargetPort: 50001, Enabled: true}
}

func TestValidate(t *testing.T) {
	a, b := secure("one.example.org", "https", 443), secure("two.example.org", "https", 443)
	if err := Validate([]state.Forward{a, b}, 8080); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []state.Forward{secure("*.example.org", "https", 443), secure("127.0.0.1", "tls", 50002), secure("two.example.org", "tls", 443), secure("two.example.org", "tls", 8080), secure("one.example.org", "https", 443), {PublicPort: 80, Protocol: "tcp"}, {PublicPort: 443, Protocol: "tcp", Enabled: false}} {
		if Validate([]state.Forward{a, bad}, 8080) == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	if err := Validate([]state.Forward{a, secure("one.example.org", "tls", 50002), secure("one.example.org", "tls", 50003)}, 8080); err != nil {
		t.Fatal("one domain must support independent public ports", err)
	}
	if Validate([]state.Forward{a, {PublicPort: 443, Protocol: "udp"}}, 8080) != nil {
		t.Fatal("UDP port should remain independent")
	}
}

func TestApplyPortConflictPreservesExistingRoutes(t *testing.T) {
	m := New(t.TempDir())
	defer m.Close()
	a := secure("web.example.org", "https", 443)
	m.routes = []state.Forward{a}
	for _, port := range []int{80, 443} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		m.listeners[port] = ln
	}
	m.listen = func(string, string) (net.Listener, error) { return nil, fmt.Errorf("occupied") }
	if m.Apply([]state.Forward{a, secure("electrs.example.org", "tls", 50002)}) == nil {
		t.Fatal("accepted occupied port")
	}
	if len(m.routes) != 1 || m.routes[0].Domain != a.Domain || len(m.listeners) != 2 {
		t.Fatal("existing configuration lost")
	}
	for _, ln := range m.listeners {
		c, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second)
		if err != nil {
			t.Fatal("existing listener closed", err)
		}
		c.Close()
	}
}

func TestHTTPProxyAndTrustedHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host+"|"+r.Header.Get("X-Forwarded-Proto")+"|"+r.Header.Get("X-Forwarded-Host")+"|"+r.Header.Get("X-Forwarded-For")+"|"+r.Header.Get("Forwarded"))
	}))
	defer backend.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	var n int
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	m := New(t.TempDir())
	defer m.Close()
	f := secure("web.example.org", "https", 443)
	f.TargetIP = host
	f.TargetPort = n
	m.routes = []state.Forward{f}
	r := httptest.NewRequest("GET", "https://web.example.org/a", nil)
	r.TLS = &tls.ConnectionState{ServerName: f.Domain}
	r.RemoteAddr = "192.0.2.1:1234"
	r.Header.Set("X-Forwarded-For", "evil")
	r.Header.Set("X-Forwarded-Proto", "http")
	r.Header.Set("Forwarded", "evil")
	w := httptest.NewRecorder()
	m.proxyHTTP(w, r)
	if got := w.Body.String(); got != "web.example.org|https|web.example.org|192.0.2.1|" {
		t.Fatalf("headers: %s", got)
	}
	r.Host = "evil.example.org"
	w = httptest.NewRecorder()
	m.proxyHTTP(w, r)
	if w.Code != 421 {
		t.Fatalf("unknown host accepted: %d", w.Code)
	}
	if m.hostPolicy(context.Background(), "evil.example.org") == nil {
		t.Fatal("unauthorized certificate host")
	}
}

func TestHTTPDomainWithoutCertificateAndSharedPort(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Host+"|"+r.Header.Get("X-Forwarded-Proto"))
	}))
	defer backend.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(backend.URL, "http://"))
	var n int
	for _, c := range port {
		n = n*10 + int(c-'0')
	}
	m := New(t.TempDir())
	defer m.Close()
	m.listen = func(string, string) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	a := secure("one.example.org", "http", 80)
	a.TargetIP = host
	a.TargetPort = n
	b := a
	b.Domain = "two.example.org"
	if err := Validate([]state.Forward{a, b}, 8080); err != nil {
		t.Fatal(err)
	}
	if err := m.Apply([]state.Forward{a, b}); err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{a.Domain, b.Domain} {
		r := httptest.NewRequest("GET", "http://"+domain+"/", nil)
		w := httptest.NewRecorder()
		m.redirect(w, r)
		if got := w.Body.String(); got != domain+"|http" {
			t.Fatalf("HTTP domain route %s: %s", domain, got)
		}
		if m.hostPolicy(context.Background(), domain) == nil {
			t.Fatal("HTTP-only domain authorized for certificate")
		}
	}
	if len(m.Status()) != 0 {
		t.Fatal("HTTP-only domains should not request certificates")
	}
	r := httptest.NewRequest("GET", "http://unknown.example.org/", nil)
	w := httptest.NewRecorder()
	m.redirect(w, r)
	if w.Code != 404 {
		t.Fatal("unknown HTTP domain routed")
	}
}

func TestCertificateDNSFailureIsActionableAndSkipsACME(t *testing.T) {
	m := New(t.TempDir())
	defer m.Close()
	f := secure("web.example.org", "https", 443)
	m.routes = []state.Forward{f}
	m.lookup = func(context.Context, string) ([]string, error) { return nil, fmt.Errorf("no such host") }
	issued := false
	m.issue = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		issued = true
		return &tls.Certificate{}, nil
	}
	m.warmOnce(map[string]time.Time{}, 30*time.Minute, false)
	if issued {
		t.Fatal("ACME attempted for a name that does not resolve")
	}
	status := m.Status()
	if len(status) != 1 || status[0]["state"] != "error" || status[0]["checked_at"] == nil {
		t.Fatalf("status: %v", status)
	}
	hint, _ := status[0]["hint"].(string)
	message, _ := status[0]["error"].(string)
	if !strings.Contains(hint, "Solo DNS") || !strings.Contains(message, "DNS:") {
		t.Fatalf("not actionable: %v", status[0])
	}
}

func TestCertificateRetryBypassesCooldownAndClearsError(t *testing.T) {
	m := New(t.TempDir())
	defer m.Close()
	f := secure("web.example.org", "https", 443)
	m.routes = []state.Forward{f}
	m.lookup = func(context.Context, string) ([]string, error) { return []string{"192.0.2.1"}, nil }
	calls := 0
	m.issue = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		calls++
		return &tls.Certificate{}, nil
	}
	m.recordError(f.Domain, fmt.Errorf("previous failure"))
	last := map[string]time.Time{}
	m.warmOnce(last, 30*time.Minute, false)
	m.warmOnce(last, 30*time.Minute, false)
	if calls != 1 {
		t.Fatalf("per-domain cooldown ignored: %d attempts", calls)
	}
	m.warmOnce(last, 30*time.Minute, true)
	if calls != 2 {
		t.Fatalf("explicit retry did not bypass cooldown: %d attempts", calls)
	}
	status := m.Status()
	if len(status) != 1 || status[0]["state"] != "pending" || status[0]["error"] != nil {
		t.Fatalf("error not cleared after success: %v", status)
	}
}

func TestCertificateHintsExplainAutocertFailures(t *testing.T) {
	hint := certHint(fmt.Errorf(`acme/autocert: unable to satisfy "https://acme-v02.api.letsencrypt.org/acme/authz/1" for domain "web.example.org": no viable challenge type found`))
	if !strings.Contains(hint, "HTTP-01") || !strings.Contains(hint, "443") {
		t.Fatalf("generic challenge hint: %s", hint)
	}
	if hint := certHint(fmt.Errorf("acme: rateLimited")); !strings.Contains(hint, "limita") {
		t.Fatalf("rate limit hint: %s", hint)
	}
}

func TestCertificateMetadataSharedAcrossPublicPorts(t *testing.T) {
	m := New(t.TempDir())
	defer m.Close()
	a := secure("electrs.example.org", "tls", 50002)
	a.Enabled = false
	b := a
	b.PublicPort = 50003
	b.Enabled = true
	m.routes = []state.Forward{a, b}
	status := m.Status()
	if len(status) != 1 || status[0]["enabled"] != true || status[0]["domain"] != a.Domain {
		t.Fatalf("shared certificate metadata: %v", status)
	}
}

func TestTCP_TLS_ToCleartextAndCertificateStatus(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err = io.ReadFull(c, buf); err == nil {
			c.Write(buf)
		}
	}()
	public, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer public.Close()
	m := New(t.TempDir())
	defer m.Close()
	f := secure("electrs.example.org", "tls", public.Addr().(*net.TCPAddr).Port)
	f.TargetPort = backend.Addr().(*net.TCPAddr).Port
	m.routes = []state.Forward{f}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: f.Domain}, DNSNames: []string{f.Domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err = m.certs.Cache.Put(context.Background(), f.Domain+"+rsa", data); err != nil {
		t.Fatal(err)
	}
	go m.serveTCP(public, f.PublicPort)
	// No SNI: Electrum clients can connect using a configured hostname without
	// sending SNI; the dedicated listener must still use its assigned certificate.
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", public.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte("ping"))
	buf := make([]byte, 4)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo %q: %v", buf, err)
	}
	status := m.Status()
	if len(status) != 1 || status[0]["state"] != "ready" {
		t.Fatalf("status: %v", status)
	}
	encoded, _ := json.Marshal(status)
	if strings.Contains(string(encoded), "PRIVATE KEY") {
		t.Fatal("private key leaked")
	}
	wrong, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", public.Addr().String(), &tls.Config{InsecureSkipVerify: true, ServerName: "wrong.example.org", MinVersion: tls.VersionTLS12})
	if err == nil {
		wrong.Close()
		t.Fatal("wrong SNI accepted")
	}
}
