package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPaths(t *testing.T) Paths {
	t.Helper()
	root := t.TempDir()
	return Paths{
		Etc:       filepath.Join(root, "etc"),
		State:     filepath.Join(root, "state"),
		WireGuard: filepath.Join(root, "wg"),
		Run:       filepath.Join(root, "run"),
	}
}

func TestSaveLoad(t *testing.T) {
	paths := testPaths(t)
	cfg := Default()
	cfg.Endpoint = "203.0.113.10"
	cfg.WGPort = 51821
	if err := cfg.Save(paths); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(paths)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Endpoint != cfg.Endpoint || loaded.WGPort != 51821 || loaded.APIListen != cfg.APIListen {
		t.Fatalf("config distinta: %+v", loaded)
	}
	info, err := os.Stat(paths.ConfigFile())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %o", info.Mode().Perm())
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	cases := []func(*Config){
		func(c *Config) { c.APIListen = "nope" },
		func(c *Config) { c.WGPort = 0 },
		func(c *Config) { c.Subnet = "10.0.0.0/33" },
		func(c *Config) { c.ServerIP = "10.1.0.1" },
		func(c *Config) { c.UmbrelIP = c.ServerIP },
		func(c *Config) { c.MTU = 10 },
		func(c *Config) { c.Interface = "wg 0" },
	}
	for i, mutate := range cases {
		cfg := Default()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("caso %d aceptado", i)
		}
	}
}

func TestToken(t *testing.T) {
	paths := testPaths(t)
	token, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 || strings.ContainsAny(token, " \n") {
		t.Fatalf("token inesperado: %q", token)
	}
	if err := paths.SaveToken(token); err != nil {
		t.Fatal(err)
	}
	loaded, err := paths.LoadToken()
	if err != nil {
		t.Fatal(err)
	}
	if loaded != token {
		t.Fatalf("token distinto")
	}
	info, _ := os.Stat(paths.TokenFile())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %o", info.Mode().Perm())
	}
}
