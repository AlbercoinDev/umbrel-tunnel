package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"umbrel-tunnel/internal/config"
)

func TestForwardCLIUsesAuthenticatedDaemonAndPartialPatch(t *testing.T) {
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("missing authentication")
		}
		if r.Method != "PATCH" || r.URL.Path != "/api/forwards/f1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if len(body) != 1 || body["public_port"] != float64(9001) {
			t.Errorf("patch changes unspecified fields: %v", body)
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	root := t.TempDir()
	t.Setenv("UMBREL_TUNNEL_ETC", filepath.Join(root, "etc"))
	t.Setenv("UMBREL_TUNNEL_STATE", filepath.Join(root, "state"))
	t.Setenv("UMBREL_TUNNEL_WIREGUARD", filepath.Join(root, "wg"))
	t.Setenv("UMBREL_TUNNEL_RUN", filepath.Join(root, "run"))
	p := config.DefaultPaths()
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.APIListen = strings.TrimPrefix(server.URL, "http://")
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	if err := p.SaveToken("test-token"); err != nil {
		t.Fatal(err)
	}
	if err := cmdForwardAPI(context.Background(), []string{"edit", "f1", "--public-port", "9001"}); err != nil {
		t.Fatal(err)
	}
	if requests != 1 {
		t.Fatalf("got %d requests", requests)
	}
}
