package state

import (
	"os"
	"path/filepath"
	"testing"

	"tunnel-wg/internal/config"
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

func TestAddUpdateRemoveForward(t *testing.T) {
	paths := testPaths(t)
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	store, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddForward(Forward{Name: "web", PublicPort: 8080, TargetIP: "10.0.0.2", TargetPort: 3006, Protocol: "tcp", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddForward(Forward{Name: "dup", PublicPort: 8080, TargetIP: "10.0.0.2", TargetPort: 3007, Protocol: "tcp", Enabled: true}); err == nil {
		t.Fatal("puerto duplicado aceptado")
	}

	forwards := store.Forwards()
	if len(forwards) != 1 || forwards[0].ID == "" {
		t.Fatalf("estado inesperado: %+v", forwards)
	}
	id := forwards[0].ID

	updated, err := store.UpdateForward(id, func(f *Forward) error {
		f.Enabled = false
		f.PublicPort = 9090
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Enabled || updated.PublicPort != 9090 {
		t.Fatalf("update no aplicado: %+v", updated)
	}

	reloaded, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Forwards(); len(got) != 1 || got[0].PublicPort != 9090 || got[0].Enabled {
		t.Fatalf("persistencia incorrecta: %+v", got)
	}

	if _, ok, err := store.RemoveForward(id); err != nil || !ok {
		t.Fatalf("remove: ok=%v err=%v", ok, err)
	}
	if len(store.Forwards()) != 0 {
		t.Fatal("forward no eliminado")
	}
}

func TestUpdateForwardRejectsDuplicateWithoutMutating(t *testing.T) {
	paths := testPaths(t)
	_ = paths.Ensure()
	store, _ := Open(paths)
	_ = store.AddForward(Forward{Name: "a", PublicPort: 1000, TargetIP: "10.0.0.2", TargetPort: 1, Protocol: "tcp", Enabled: true})
	_ = store.AddForward(Forward{Name: "b", PublicPort: 2000, TargetIP: "10.0.0.2", TargetPort: 2, Protocol: "tcp", Enabled: true})

	var id string
	for _, f := range store.Forwards() {
		if f.PublicPort == 2000 {
			id = f.ID
		}
	}
	if _, err := store.UpdateForward(id, func(f *Forward) error {
		f.PublicPort = 1000
		return nil
	}); err == nil {
		t.Fatal("duplicado aceptado")
	}
	for _, f := range store.Forwards() {
		if f.ID == id && f.PublicPort != 2000 {
			t.Fatalf("estado mutado tras error: %+v", f)
		}
	}
}

func TestForwardRejectsReservedSSHPort(t *testing.T) {
	paths := testPaths(t)
	_ = paths.Ensure()
	store, _ := Open(paths)
	if err := store.AddForward(Forward{Name: "ssh", PublicPort: 22, TargetIP: "10.0.0.2", TargetPort: 22, Protocol: "tcp", Enabled: true}); err == nil {
		t.Fatal("se permitió abrir el puerto público 22")
	}
	if err := store.AddForward(Forward{Name: "ok", PublicPort: 2222, TargetIP: "10.0.0.2", TargetPort: 22, Protocol: "tcp", Enabled: true}); err != nil {
		t.Fatalf("2222 rechazado: %v", err)
	}
	id := store.Forwards()[0].ID
	if _, err := store.UpdateForward(id, func(f *Forward) error {
		f.PublicPort = 22
		return nil
	}); err == nil {
		t.Fatal("se permitió cambiar un forward al puerto público 22")
	}
}

func TestLegacyForwardMigration(t *testing.T) {
	paths := testPaths(t)
	_ = paths.Ensure()
	legacy := `[{"id":"abc","name":"old","dport":8333,"target_ip":"10.0.0.2","target_port":8333,"auth_mode":"none","enabled":true}]`
	if err := os.WriteFile(paths.ForwardsFile(), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	forwards := store.Forwards()
	if len(forwards) != 1 {
		t.Fatalf("esperado 1 forward, got %d", len(forwards))
	}
	if forwards[0].PublicPort != 8333 || forwards[0].Protocol != "tcp" || !forwards[0].Enabled {
		t.Fatalf("migración incorrecta: %+v", forwards[0])
	}
}
