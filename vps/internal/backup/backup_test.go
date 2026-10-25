package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/fsutil"
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

func seed(t *testing.T, paths config.Paths) {
	t.Helper()
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		paths.ConfigFile():    `{"version":"1"}`,
		paths.TokenFile():     "secret-token\n",
		paths.ClientKeyFile(): "client-key\n",
		paths.ServerKeyFile(): "server-key\n",
		paths.ServerPubFile(): "server-pub\n",
		paths.RulesFile():     "table inet tunnel_wg {}\n",
		paths.PeersFile():     "[]\n",
		paths.ForwardsFile():  "[]\n",
		paths.WGConfFile():    "# Managed by tunnel-wg\n",
	}
	for path, content := range files {
		if err := fsutil.WriteString(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	src := testPaths(t)
	seed(t, src)

	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatalf("Create: %v", err)
	}

	dst := testPaths(t)
	if err := Restore(bytes.NewReader(buf.Bytes()), dst, false); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	data, err := os.ReadFile(dst.TokenFile())
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "secret-token\n" {
		t.Fatalf("token restaurado: %q", data)
	}
	info, _ := os.Stat(dst.TokenFile())
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("permisos: %o", info.Mode().Perm())
	}
}

func TestRestoreRefusesExistingWithoutForce(t *testing.T) {
	src := testPaths(t)
	seed(t, src)

	var buf bytes.Buffer
	if err := Create(&buf, src); err != nil {
		t.Fatal(err)
	}

	dst := testPaths(t)
	seed(t, dst)
	if err := Restore(bytes.NewReader(buf.Bytes()), dst, false); err == nil {
		t.Fatal("sobrescribió sin --force")
	}
	if err := Restore(bytes.NewReader(buf.Bytes()), dst, true); err != nil {
		t.Fatalf("force: %v", err)
	}
}

func TestRestoreRejectsUnknownEntries(t *testing.T) {
	dst := testPaths(t)
	if err := Restore(bytes.NewReader([]byte("not a tarball")), dst, true); err == nil {
		t.Fatal("archivo inválido aceptado")
	}
}
