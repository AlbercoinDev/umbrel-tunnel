package httpapi

import (
	"encoding/json"
	"testing"
	"umbrel-tunnel/internal/state"
)

func TestSecurePublications(t *testing.T) {
	h := newHarness(t)
	create := func(domain, mode string, port int) state.Forward {
		t.Helper()
		resp, body := h.do("POST", "/api/forwards", h.token, map[string]any{"name": domain, "domain": domain, "access_mode": mode, "public_port": port, "target_ip": "10.0.0.2", "target_port": 20000, "accept_acme_terms": true})
		var f state.Forward
		h.decode(resp, body, &f)
		return f
	}
	a := create("web.example.org", "https", 443)
	create("bin.example.org", "https", 443)
	create("electrs.example.org", "tls", 50002)
	resp, body := h.do("POST", "/api/forwards", h.token, map[string]any{"name": "direct", "public_port": 80, "target_ip": "10.0.0.2", "target_port": 20000})
	if resp.StatusCode != 400 {
		t.Fatalf("direct80: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("PATCH", "/api/forwards/"+a.ID, h.token, map[string]any{"domain": "other.example.org"})
	if resp.StatusCode != 400 {
		t.Fatalf("terms missing: %d %s", resp.StatusCode, body)
	}
	resp, body = h.do("GET", "/api/forwards", h.token, nil)
	var forwards []state.Forward
	h.decode(resp, body, &forwards)
	if len(forwards) != 3 || forwards[0].Domain != a.Domain {
		t.Fatalf("state altered: %s", body)
	}
	resp, _ = h.do("GET", "/api/certificates", "", nil)
	if resp.StatusCode != 401 {
		t.Fatal("certificate metadata must require auth")
	}
	// Disk reload retains secure mode/domain (not just in-memory API metadata).
	store, err := state.Open(h.paths)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(store.Forwards())
	if len(store.Forwards()) != 3 || store.Forwards()[0].AccessMode != "https" {
		t.Fatalf("reload: %s", data)
	}
}

func TestSameDomainPlainTLSAndHTTPPublications(t *testing.T) {
	h := newHarness(t)
	for _, entry := range []struct {
		domain, mode string
		port         int
	}{{"electrs.example.org", "direct", 50001}, {"electrs.example.org", "tls", 50002}, {"electrs.example.org", "tls", 50003}, {"one.example.org", "http", 80}, {"two.example.org", "http", 80}} {
		resp, body := h.do("POST", "/api/forwards", h.token, map[string]any{"name": entry.domain, "domain": entry.domain, "access_mode": entry.mode, "public_port": entry.port, "target_ip": "10.0.0.2", "target_port": 20000, "accept_acme_terms": true})
		var f state.Forward
		h.decode(resp, body, &f)
		if f.Domain != entry.domain || f.PublicPort != entry.port {
			t.Fatalf("publication altered: %s", body)
		}
	}
	resp, body := h.do("GET", "/api/forwards", h.token, nil)
	var forwards []state.Forward
	h.decode(resp, body, &forwards)
	if len(forwards) != 5 {
		t.Fatalf("expected independent publications: %s", body)
	}
}
