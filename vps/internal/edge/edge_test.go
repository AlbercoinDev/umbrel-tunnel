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
	for _, bad := range []state.Forward{secure("*.example.org", "https", 443), secure("127.0.0.1", "tls", 50002), secure("two.example.org", "tls", 443), secure("two.example.org", "tls", 8080), secure("one.example.org", "tls", 50002), {PublicPort: 80, Protocol: "tcp"}, {PublicPort: 443, Protocol: "tcp", Enabled: false}} {
		if Validate([]state.Forward{a, bad}, 8080) == nil {
			t.Fatalf("accepted %+v", bad)
		}
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
