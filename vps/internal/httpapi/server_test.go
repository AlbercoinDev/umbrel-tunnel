package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/execx"
	"tunnel-wg/internal/service"
	"tunnel-wg/internal/state"
)

type harness struct {
	t       *testing.T
	server  *httptest.Server
	token   string
	umbrel  state.Peer
	handler http.Handler
	paths   config.Paths
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root := t.TempDir()
	paths := config.Paths{
		Etc:       filepath.Join(root, "etc"),
		State:     filepath.Join(root, "state"),
		WireGuard: filepath.Join(root, "wg"),
		Run:       filepath.Join(root, "run"),
	}
	run := &execx.Fake{Outputs: map[string][]byte{
		"wg genkey": []byte("cHJpdmF0ZS1rZXktZm9yLXRlc3Rz\n"),
		"wg pubkey": []byte("cHVibGljLWtleS1mb3ItdGVzdHM=\n"),
	}}
	_, pairing, err := service.Initialize(context.Background(), paths, run, service.InitOptions{
		Endpoint: "203.0.113.10",
		Token:    "test-token",
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	svc, err := service.Open(paths, run)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := svc.Store.PeerByIP("10.0.0.2")
	if !ok {
		t.Fatal("peer de Umbrel ausente")
	}

	h := &harness{t: t, token: pairing.Token, umbrel: peer, paths: paths}
	h.handler = New(svc, "test", run).Handler()
	h.server = httptest.NewServer(h.handler)
	t.Cleanup(h.server.Close)
	return h
}

func (h *harness) do(method, path, token string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			h.t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, h.server.URL+path, reader)
	if err != nil {
		h.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := h.server.Client().Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

func (h *harness) decode(resp *http.Response, body []byte, dst any) {
	h.t.Helper()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.t.Fatalf("HTTP %d: %s", resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		h.t.Fatalf("JSON inválido: %v (%s)", err, body)
	}
}

func TestHealthNeedsNoAuth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodGet, "/health", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP %d: %s", resp.StatusCode, body)
	}
}

func TestAuthRequired(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodGet, "/api/status", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HTTP %d", resp.StatusCode)
	}
	resp, _ = h.do(http.MethodGet, "/api/status", "wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token inválido aceptado: HTTP %d", resp.StatusCode)
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodGet, "/api/status", h.token, nil)
	var got statusResponse
	h.decode(resp, body, &got)
	if got.Version != "test" || got.PeersTotal != 1 || got.Peers[0].AllowedIP != "10.0.0.2" {
		t.Fatalf("status inesperado: %+v", got)
	}
}

func TestForwardLifecycle(t *testing.T) {
	h := newHarness(t)

	resp, body := h.do(http.MethodPost, "/api/forwards", h.token, map[string]any{
		"name": "web", "public_port": 8080, "target_ip": "10.0.0.2",
		"target_port": 3006, "protocol": "tcp", "enabled": true,
	})
	var created state.Forward
	h.decode(resp, body, &created)
	if created.PublicPort != 8080 || created.ID == "" {
		t.Fatalf("forward creado: %+v", created)
	}

	resp, _ = h.do(http.MethodPost, "/api/forwards", h.token, map[string]any{
		"name": "dup", "public_port": 8080, "target_ip": "10.0.0.2",
		"target_port": 3006, "protocol": "tcp",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicado: HTTP %d", resp.StatusCode)
	}

	resp, body = h.do(http.MethodPatch, "/api/forwards/"+created.ID, h.token, map[string]any{"enabled": false})
	var patched state.Forward
	h.decode(resp, body, &patched)
	if patched.Enabled {
		t.Fatal("patch no aplicado")
	}

	resp, body = h.do(http.MethodGet, "/api/forwards", h.token, nil)
	var list []state.Forward
	h.decode(resp, body, &list)
	if len(list) != 1 || list[0].Enabled {
		t.Fatalf("lista: %+v", list)
	}

	resp, body = h.do(http.MethodDelete, "/api/forwards/"+created.ID, h.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete: HTTP %d %s", resp.StatusCode, body)
	}
	resp, body = h.do(http.MethodGet, "/api/forwards", h.token, nil)
	h.decode(resp, body, &list)
	if len(list) != 0 {
		t.Fatalf("forward no eliminado: %+v", list)
	}
}

func TestForwardValidation(t *testing.T) {
	h := newHarness(t)
	cases := []map[string]any{
		{"name": "x", "public_port": 0, "target_ip": "10.0.0.2", "target_port": 1},
		{"name": "x", "public_port": 8080, "target_ip": "10.9.9.9", "target_port": 1},
		{"name": "x", "public_port": 8080, "target_ip": "10.0.0.2", "target_port": 1, "protocol": "sctp"},
		{"name": strings.Repeat("x", 65), "public_port": 8080, "target_ip": "10.0.0.2", "target_port": 1},
	}
	for i, body := range cases {
		resp, raw := h.do(http.MethodPost, "/api/forwards", h.token, body)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("caso %d: HTTP %d %s", i, resp.StatusCode, raw)
		}
	}
}

func TestPeerLifecycle(t *testing.T) {
	h := newHarness(t)

	pub := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	resp, body := h.do(http.MethodPost, "/api/peers", h.token, map[string]any{
		"name": "laptop", "allowed_ip": "10.0.0.3", "public_key": pub,
	})
	var created peerResponse
	h.decode(resp, body, &created)
	if created.ID == "" || created.PublicKey != pub {
		t.Fatalf("peer creado: %+v", created)
	}

	resp, body = h.do(http.MethodGet, "/api/peers", h.token, nil)
	var peers []state.Peer
	h.decode(resp, body, &peers)
	if len(peers) != 2 {
		t.Fatalf("peers: %+v", peers)
	}

	resp, body = h.do(http.MethodGet, "/api/peers/"+h.umbrel.ID+"/config", h.token, nil)
	var cfg map[string]string
	h.decode(resp, body, &cfg)
	if cfg["config"] == "" {
		t.Fatal("configuración vacía")
	}

	resp, body = h.do(http.MethodDelete, "/api/peers/"+created.ID, h.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete peer: HTTP %d %s", resp.StatusCode, body)
	}

	resp, _ = h.do(http.MethodPost, "/api/peers", h.token, map[string]any{
		"name": "dup", "allowed_ip": "10.0.0.2",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("IP duplicada: HTTP %d", resp.StatusCode)
	}
}

func TestTokenRotation(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodPost, "/api/token/rotate", h.token, nil)
	var rotated map[string]string
	h.decode(resp, body, &rotated)
	if rotated["token"] == "" || rotated["token"] == h.token {
		t.Fatalf("token no rotado: %+v", rotated)
	}

	resp, _ = h.do(http.MethodGet, "/api/status", h.token, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token antiguo sigue válido: HTTP %d", resp.StatusCode)
	}
	resp, _ = h.do(http.MethodGet, "/api/status", rotated["token"], nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token nuevo rechazado: HTTP %d", resp.StatusCode)
	}
}

func TestDashboardAssets(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		resp, body := h.do(http.MethodGet, path, "", nil)
		if resp.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("%s: HTTP %d (%d bytes)", path, resp.StatusCode, len(body))
		}
	}
	resp, _ := h.do(http.MethodGet, "/nope", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("ruta desconocida: HTTP %d", resp.StatusCode)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(http.MethodGet, "/health", "", nil)
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("falta X-Content-Type-Options")
	}
	if resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("falta CSP")
	}
}
