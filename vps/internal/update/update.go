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
	"runtime"
	"strings"
	"time"

	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/units"
)

const (
	maxBinarySize = 100 << 20
	repo          = "AlbercoinDev/umbrel-tunnel"
)

// Test seams: the real host and the test binary both need a deterministic path.
var (
	selfPath  = os.Executable
	unitsRoot = "/"
)

// Result describes what changed.
type Result struct {
	Path string
	From string
	To   string
}

// Options configures an update.
type Options struct {
	// Source is a URL or path. Empty selects the latest release for GOARCH.
	Source  string
	SHA256  string
	Restart bool
	Units   bool
	Runner  execx.Runner
}

// DefaultSource is the stable release URL for the running architecture.
func DefaultSource() string {
	return fmt.Sprintf("https://github.com/%s/releases/latest/download/umbrel-tunnel-linux-%s", repo, runtime.GOARCH)
}

// Apply downloads or reads a new binary, verifies its checksum, checks that it
// runs, replaces the current executable atomically, refreshes the systemd
// units and optionally restarts the service.
func Apply(ctx context.Context, opts Options) (Result, error) {
	var res Result
	run := opts.Runner
	if run == nil {
		run = execx.Real{}
	}
	exe, err := selfPath()
	if err != nil {
		return res, err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return res, err
	}
	res.Path = exe
	res.From = version(ctx, exe)

	source := strings.TrimSpace(opts.Source)
	if source == "" {
		source = DefaultSource()
	}

	data, err := read(ctx, source)
	if err != nil {
		return res, err
	}
	if len(data) == 0 {
		return res, fmt.Errorf("binario vacío")
	}
	if len(data) > maxBinarySize {
		return res, fmt.Errorf("binario demasiado grande")
	}

	wantSHA := opts.SHA256
	if wantSHA == "" {
		// Try a sidecar checksum next to the source.
		wantSHA = trySidecar(ctx, source)
	}
	if wantSHA != "" {
		sum := sha256.Sum256(data)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, strings.TrimSpace(wantSHA)) {
			return res, fmt.Errorf("checksum no coincide: esperado %s, obtenido %s", wantSHA, got)
		}
	}

	previous, _ := os.ReadFile(exe)
	dir := filepath.Dir(exe)
	tmp := filepath.Join(dir, ".umbrel-tunnel.new")
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return res, fmt.Errorf("escribir %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		_ = os.Remove(tmp)
		return res, fmt.Errorf("reemplazar binario: %w", err)
	}

	// A binary that does not run (wrong architecture, truncated download) must
	// not leave the host without a working control plane.
	res.To = version(ctx, exe)
	if res.To == "" {
		if len(previous) > 0 {
			_ = os.WriteFile(tmp, previous, 0o755)
			if restore := os.Rename(tmp, exe); restore != nil {
				return res, fmt.Errorf("el binario nuevo no se ejecuta y la restauración falló: %w", restore)
			}
			return res, fmt.Errorf("el binario nuevo no se ejecuta; se restauró %s", res.From)
		}
		return res, fmt.Errorf("el binario nuevo no se ejecuta (comprueba la arquitectura)")
	}

	if opts.Units {
		if err := units.Install(unitsRoot); err != nil {
			return res, fmt.Errorf("actualizar unidades systemd: %w", err)
		}
		if _, err := run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return res, fmt.Errorf("systemctl daemon-reload: %w", err)
		}
	}

	if opts.Restart {
		if _, err := run.Run(ctx, "systemctl", "restart", "umbrel-tunnel"); err != nil {
			return res, restartFailure(ctx, run, err)
		}
	}
	return res, nil
}

// version runs `<exe> version` and returns the first line, or "" when the file
// cannot be executed.
func version(ctx context.Context, exe string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := execx.Real{}.Run(ctx, exe, "version")
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func restartFailure(ctx context.Context, run execx.Runner, cause error) error {
	tail, _ := run.Run(ctx, "journalctl", "-u", "umbrel-tunnel", "-n", "20", "--no-pager")
	detail := strings.TrimSpace(string(tail))
	if len(detail) > 2000 {
		detail = detail[len(detail)-2000:]
	}
	if detail == "" {
		return fmt.Errorf("binario actualizado pero el reinicio falló: %w", cause)
	}
	return fmt.Errorf("binario actualizado pero el reinicio falló: %w\n%s", cause, detail)
}

func read(ctx context.Context, source string) ([]byte, error) {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return download(ctx, source)
	}
	return os.ReadFile(source)
}

func download(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "umbrel-tunnel")
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
