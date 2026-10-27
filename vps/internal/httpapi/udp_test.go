package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"

	"umbrel-tunnel/internal/state"
)

func TestUDPForwardLifecycleAndSharedPort(t *testing.T) {
	h := newHarness(t)
	for _, proto := range []string{"tcp", "udp"} {
		resp, data := h.do("POST", "/api/forwards", h.token, map[string]any{
			"name": "test-" + proto, "public_port": 9000, "target_ip": "10.0.0.2", "target_port": 23000,
			"protocol": proto, "managed_by": "umbrel:10.0.0.2",
		})
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d %s", proto, resp.StatusCode, data)
		}
		var rule state.Forward
		if err := json.Unmarshal(data, &rule); err != nil {
			t.Fatal(err)
		}
		if rule.ManagedBy != "umbrel:10.0.0.2" {
			t.Fatal("owner missing")
		}
		if proto == "tcp" {
			continue
		}
		res, body := h.do("PATCH", "/api/forwards/"+rule.ID, h.token, map[string]any{
			"name": rule.Name, "public_port": rule.PublicPort, "target_ip": rule.TargetIP,
			"target_port": rule.TargetPort, "protocol": rule.Protocol, "enabled": true, "managed_by": rule.ManagedBy,
		})
		if res.StatusCode != 200 {
			t.Fatalf("full gateway payload: %s", body)
		}
		for _, enabled := range []bool{false, true} {
			res, body := h.do("PATCH", "/api/forwards/"+rule.ID, h.token, map[string]bool{"enabled": enabled})
			if res.StatusCode != 200 {
				t.Fatalf("toggle: %s", body)
			}
		}
		res, body = h.do("PATCH", "/api/forwards/"+rule.ID, h.token, map[string]int{"public_port": 9001})
		if res.StatusCode != 200 {
			t.Fatalf("edit: %s", body)
		}
		res, body = h.do("DELETE", "/api/forwards/"+rule.ID, h.token, nil)
		if res.StatusCode != 200 {
			t.Fatalf("delete: %s", body)
		}
	}
	resp, data := h.do("POST", "/api/forwards/reconcile", h.token, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("reconcile: %s", data)
	}
	store, err := state.Open(h.paths)
	if err != nil {
		t.Fatal(err)
	}
	if store.Forwards()[0].ManagedBy != "umbrel:10.0.0.2" {
		t.Fatal("owner not persisted")
	}
}

func TestWireGuardUDPPortReserved(t *testing.T) {
	h := newHarness(t)
	resp, data := h.do("POST", "/api/forwards", h.token, map[string]any{
		"public_port": 51820, "target_ip": "10.0.0.2", "target_port": 1234, "protocol": "udp",
	})
	if resp.StatusCode != 400 {
		t.Fatalf("reserved UDP port accepted: %d %s", resp.StatusCode, data)
	}
}
