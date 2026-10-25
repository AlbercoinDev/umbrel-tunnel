// Package update replaces the running binary safely.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tunnel-wg/internal/execx"
)

const maxBinarySize = 100 << 20

// Apply downloads or reads a new binary, verifies its checksum (optional),
// replaces the current executable atomically and optionally restarts systemd.
func Apply(ctx context.Context, source, wantSHA string, restart bool, run execx.Runner) (string, error) {
	if strings.TrimSpace(source) == "" {
		return "", fmt.Errorf("falta --from")
	}

	var data []byte
	var err error
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		data, err = download(ctx, source)
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("binario vacío")
	}
	if len(data) > maxBinarySize {
		return "", fmt.Errorf("binario demasiado grande")
	}

	if wantSHA == "" {
		// Try a sidecar checksum next to the source.
		wantSHA = trySidecar(ctx, source)
	}
	if wantSHA != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, strings.TrimSpace(wantSHA)) {
			return "", fmt.Errorf("checksum no coincide: esperado %s, obtenido %s", wantSHA, got)
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, ".tunnel-wg.new")
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return "", fmt.Errorf("escribir %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("reemplazar binario: %w", err)
	}

	if restart {
		if _, err := run.Run(ctx, "systemctl", "restart", "tunnel-wg"); err != nil {
			return exe, fmt.Errorf("binario actualizado pero el reinicio falló: %w", err)
		}
	}
	return exe, nil
}

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "tunnel-wg")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("descargar %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBinarySize+1))
}

func trySidecar(ctx context.Context, source string) string {
	if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		data, err := os.ReadFile(source + ".sha256")
		if err != nil {
			return ""
		}
		fields := strings.Fields(string(data))
		if len(fields) == 0 {
			return ""
		}
		return fields[0]
	}
	data, err := download(ctx, source+".sha256")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}
