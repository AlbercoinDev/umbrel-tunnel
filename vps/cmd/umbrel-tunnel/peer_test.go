package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/state"
)

func TestPeerConfigRequiresMatchingPrivateKey(t *testing.T) {
	root := t.TempDir()
	for name, dir := range map[string]string{"ETC": "etc", "STATE": "state", "WIREGUARD": "wg", "RUN": "run"} {
		t.Setenv("UMBREL_TUNNEL_"+name, filepath.Join(root, dir))
	}
	p := paths()
	if err := p.Ensure(); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Endpoint = "203.0.113.10"
	if err := cfg.Save(p); err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	other := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{10}, 32))
	store, err := state.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddPeer(state.Peer{ID: "p1", Name: "test", AllowedIP: "10.0.0.3", PublicKey: pub}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.ServerPubFile(), []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nread -r key\nif [ \"$key\" = '" + key + "' ]; then echo '" + pub + "'; else echo '" + other + "'; fi\n"
	if err := os.WriteFile(filepath.Join(bin, "wg"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	file := filepath.Join(root, "client.key")
	if err := os.WriteFile(file, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := cmdPeer(ctx, []string{"config", "p1"}); err == nil {
		t.Fatal("missing private key accepted")
	}
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	err = cmdPeer(ctx, []string{"config", "p1", "--private-key-file", file})
	os.Stdout = old
	w.Close()
	data, _ := io.ReadAll(r)
	r.Close()
	if err != nil || !strings.Contains(string(data), "PrivateKey = "+key) || !strings.Contains(string(data), "10.0.0.3/") {
		t.Fatal("matching key failed", err)
	}
	if err := os.WriteFile(file, []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPeer(ctx, []string{"config", "p1", "--private-key-file", file}); err == nil {
		t.Fatal("wrong peer key accepted")
	}
	if err := os.WriteFile(p.ClientKeyFile(), []byte(other), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdPeer(ctx, []string{"config", "p1"}); err == nil {
		t.Fatal("wrong legacy key accepted")
	}
}
