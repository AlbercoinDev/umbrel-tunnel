package service

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/execx"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		Etc:       filepath.Join(root, "etc"),
		State:     filepath.Join(root, "state"),
		WireGuard: filepath.Join(root, "wg"),
		Run:       filepath.Join(root, "run"),
	}
}

func fakeRunner() *execx.Fake {
	return &execx.Fake{Outputs: map[string][]byte{
		"wg genkey": []byte("cHJpdmF0ZS1rZXktZm9yLXRlc3Rz\n"),
		"wg pubkey": []byte("cHVibGljLWtleS1mb3ItdGVzdHM=\n"),
	}}
}

func TestBuildConfigPublicAPIListensEverywhere(t *testing.T) {
	cfg, err := buildConfig(context.Background(), InitOptions{
		Endpoint:  "203.0.113.10",
		PublicAPI: true,
	})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.APIListen != "0.0.0.0:8080" {
		t.Fatalf("APIListen con --public-api: %q", cfg.APIListen)
	}

	cfg, err = buildConfig(context.Background(), InitOptions{
		Endpoint:  "203.0.113.10",
		PublicAPI: true,
		APIPort:   9090,
	})
	if err != nil {
		t.Fatalf("buildConfig: %v", err)
	}
	if cfg.APIListen != "0.0.0.0:9090" {
		t.Fatalf("APIListen con --public-api --api-port: %q", cfg.APIListen)
	}
}

func TestInitializeCreatesEverything(t *testing.T) {
	paths := testPaths(t)
	run := fakeRunner()
	svc, p, err := Initialize(context.Background(), paths, run, InitOptions{
		Endpoint: "203.0.113.10",
		WGPort:   51820,
	})
	if err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if svc.Cfg.Endpoint != "203.0.113.10" {
		t.Fatalf("endpoint: %q", svc.Cfg.Endpoint)
	}
	if p.API != "http://10.0.0.1:8080" {
		t.Fatalf("api: %q", p.API)
	}
	if p.Token == "" || p.WG == "" {
		t.Fatalf("pairing incompleto: %+v", p)
	}

	for _, path := range []string{
		paths.ConfigFile(), paths.TokenFile(), paths.ServerKeyFile(),
		paths.ServerPubFile(), paths.ClientKeyFile(), paths.WGConfFile(),
		paths.RulesFile(), paths.PeersFile(),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("falta %s: %v", path, err)
		}
	}

	peers := svc.Store.Peers()
	if len(peers) != 1 || peers[0].AllowedIP != "10.0.0.2" || peers[0].Name != "umbrel" {
		t.Fatalf("peers inesperados: %+v", peers)
	}

	if !run.Called("wg", "syncconf", "wg0", paths.SyncConfFile()) {
		t.Fatal("no se aplicó wg syncconf")
	}
	if !run.Called("nft", "-f", paths.RulesFile()) {
		t.Fatal("no se aplicó nftables")
	}
	if !run.Called("nft", "-c", "-f", paths.RulesFile()) {
		t.Fatal("no se validó nftables")
	}
}

func TestInitializeIsIdempotent(t *testing.T) {
	paths := testPaths(t)
	opts := InitOptions{Endpoint: "203.0.113.10"}

	_, first, err := Initialize(context.Background(), paths, fakeRunner(), opts)
	if err != nil {
		t.Fatal(err)
	}
	svc, second, err := Initialize(context.Background(), paths, fakeRunner(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token != second.Token || first.WG != second.WG {
		t.Fatalf("pairing cambió:\n%+v\n%+v", first, second)
	}
	if len(svc.Store.Peers()) != 1 {
		t.Fatalf("peers duplicados: %+v", svc.Store.Peers())
	}
}

func TestInitializeManualPubkey(t *testing.T) {
	paths := testPaths(t)
	pub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	svc, p, err := Initialize(context.Background(), paths, fakeRunner(), InitOptions{
		Endpoint:     "203.0.113.10",
		UmbrelPubKey: pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	peers := svc.Store.Peers()
	if len(peers) != 1 || peers[0].PublicKey != pub {
		t.Fatalf("peer manual incorrecto: %+v", peers)
	}
	if p.WG != "" {
		t.Fatal("modo manual no debe incluir configuración de cliente")
	}
	if _, err := os.Stat(paths.ClientKeyFile()); !os.IsNotExist(err) {
		t.Fatal("modo manual no debe generar clave de cliente")
	}
}

func TestInitializeRejectsInvalidPubkey(t *testing.T) {
	paths := testPaths(t)
	_, _, err := Initialize(context.Background(), paths, fakeRunner(), InitOptions{
		Endpoint:     "203.0.113.10",
		UmbrelPubKey: "no-es-una-clave",
	})
	if err == nil {
		t.Fatal("clave inválida aceptada")
	}
}

func TestInitializeRejectsBadEndpoint(t *testing.T) {
	paths := testPaths(t)
	_, _, err := Initialize(context.Background(), paths, fakeRunner(), InitOptions{
		Endpoint: "203.0.113.10",
		Subnet:   "10.0.0.0/33",
	})
	if err == nil {
		t.Fatal("subred inválida aceptada")
	}
}

func TestValidateIPInSubnet(t *testing.T) {
	paths := testPaths(t)
	svc, _, err := Initialize(context.Background(), paths, fakeRunner(), InitOptions{Endpoint: "203.0.113.10"})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "10.0.1.5", "10.0.0.1", "nope"} {
		if err := svc.ValidateIPInSubnet(bad); err == nil {
			t.Fatalf("IP %q aceptada", bad)
		}
	}
	if err := svc.ValidateIPInSubnet("10.0.0.3"); err != nil {
		t.Fatalf("IP válida rechazada: %v", err)
	}
}
