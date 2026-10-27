package units

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesEveryFileBelowRoot(t *testing.T) {
	root := t.TempDir()
	if err := Install(root); err != nil {
		t.Fatal(err)
	}
	for _, file := range Files {
		path := filepath.Join(root, file.Path)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("%s: permisos %o", path, info.Mode().Perm())
		}
		if info.Size() == 0 {
			t.Fatalf("%s está vacío", path)
		}
	}
}

func TestServiceUnitAllowsLowPorts(t *testing.T) {
	data, err := Content("umbrel-tunnel.service")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "CAP_NET_BIND_SERVICE") {
		t.Fatal("la unidad no permite 80/443")
	}
	if !strings.Contains(text, "AmbientCapabilities") {
		t.Fatal("faltan AmbientCapabilities")
	}
}
