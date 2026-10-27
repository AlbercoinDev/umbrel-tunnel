package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/units"
)

func script(version string) []byte {
	return []byte("#!/bin/sh\necho " + version + "\n")
}

func serve(t *testing.T, data []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(data)
	mux := http.NewServeMux()
	mux.HandleFunc("/bin", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/bin.sha256", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  bin\n", hex.EncodeToString(sum[:]))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func sandbox(t *testing.T, current []byte) (exe, root string) {
	t.Helper()
	dir := t.TempDir()
	exe = filepath.Join(dir, "umbrel-tunnel")
	if err := os.WriteFile(exe, current, 0o755); err != nil {
		t.Fatal(err)
	}
	root = t.TempDir()
	oldSelf, oldRoot := selfPath, unitsRoot
	selfPath = func() (string, error) { return exe, nil }
	unitsRoot = root
	t.Cleanup(func() { selfPath, unitsRoot = oldSelf, oldRoot })
	return exe, root
}

func TestApplyReplacesBinaryVerifiesVersionAndWritesUnits(t *testing.T) {
	exe, root := sandbox(t, script("1.3.1"))
	server := serve(t, script("1.3.2"))
	run := &execx.Fake{}

	result, err := Apply(context.Background(), Options{
		Source:  server.URL + "/bin",
		Restart: true,
		Units:   true,
		Runner:  run,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.From != "1.3.1" || result.To != "1.3.2" {
		t.Fatalf("versiones: %+v", result)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(script("1.3.2")) {
		t.Fatalf("binario no sustituido: %q", data)
	}
	for _, file := range units.Files {
		path := filepath.Join(root, file.Path)
		installed, err := os.ReadFile(path)
		want, _ := units.Content(file.Name)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if string(installed) != string(want) {
			t.Fatalf("%s no coincide con el embebido", path)
		}
	}
	if !run.Called("systemctl", "daemon-reload") || !run.Called("systemctl", "restart", "umbrel-tunnel") {
		t.Fatalf("no se recargaron unidades o no se reinició: %+v", run.Calls)
	}
}

func TestApplyRejectsChecksumMismatchWithoutTouchingBinary(t *testing.T) {
	exe, _ := sandbox(t, script("1.3.1"))
	server := serve(t, script("1.3.2"))
	_, err := Apply(context.Background(), Options{
		Source: server.URL + "/bin",
		SHA256: strings.Repeat("0", 64),
		Runner: &execx.Fake{},
	})
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("error esperado: %v", err)
	}
	data, _ := os.ReadFile(exe)
	if string(data) != string(script("1.3.1")) {
		t.Fatalf("el binario cambió pese al checksum: %q", data)
	}
}

func TestApplyRollsBackWhenNewBinaryCannotRun(t *testing.T) {
	exe, _ := sandbox(t, script("1.3.1"))
	server := serve(t, []byte("not an executable\n"))
	_, err := Apply(context.Background(), Options{
		Source: server.URL + "/bin",
		Runner: &execx.Fake{},
	})
	if err == nil || !strings.Contains(err.Error(), "no se ejecuta") {
		t.Fatalf("error esperado: %v", err)
	}
	data, _ := os.ReadFile(exe)
	if string(data) != string(script("1.3.1")) {
		t.Fatalf("no se restauró el binario anterior: %q", data)
	}
}

func TestApplyReportsJournalWhenRestartFails(t *testing.T) {
	_, _ = sandbox(t, script("1.3.1"))
	server := serve(t, script("1.3.2"))
	run := &execx.Fake{
		Outputs: map[string][]byte{
			"journalctl -u umbrel-tunnel -n 20 --no-pager": []byte("unidad en bucle de reinicio"),
		},
		Errors: map[string]error{
			"systemctl restart umbrel-tunnel": fmt.Errorf("exit 1"),
		},
	}
	_, err := Apply(context.Background(), Options{
		Source:  server.URL + "/bin",
		Restart: true,
		Runner:  run,
	})
	if err == nil || !strings.Contains(err.Error(), "unidad en bucle de reinicio") {
		t.Fatalf("falta el journal en el error: %v", err)
	}
}

func TestDefaultSourceIsStableForTheArchitecture(t *testing.T) {
	source := DefaultSource()
	if !strings.HasPrefix(source, "https://github.com/AlbercoinDev/umbrel-tunnel/releases/latest/download/umbrel-tunnel-linux-") {
		t.Fatalf("URL inesperada: %s", source)
	}
	if !strings.HasSuffix(source, "-amd64") && !strings.HasSuffix(source, "-arm64") {
		t.Fatalf("arquitectura inesperada: %s", source)
	}
}
