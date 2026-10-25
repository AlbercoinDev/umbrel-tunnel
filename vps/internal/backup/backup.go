// Package backup creates and restores small configuration archives.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/fsutil"
)

type entry struct {
	name string
	path string
	perm os.FileMode
}

func entries(paths config.Paths) []entry {
	return []entry{
		{"etc/config.json", paths.ConfigFile(), 0o600},
		{"etc/token", paths.TokenFile(), 0o600},
		{"etc/umbrel.key", paths.ClientKeyFile(), 0o600},
		{"etc/server.key", paths.ServerKeyFile(), 0o600},
		{"etc/server.pub", paths.ServerPubFile(), 0o600},
		{"etc/rules.nft", paths.RulesFile(), 0o644},
		{"state/peers.json", paths.PeersFile(), 0o600},
		{"state/forwards.json", paths.ForwardsFile(), 0o600},
		{"wireguard/wg0.conf", paths.WGConfFile(), 0o600},
	}
}

// Create writes a gzipped tarball with configuration and state.
func Create(w io.Writer, paths config.Paths) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)

	for _, e := range entries(paths) {
		data, err := os.ReadFile(e.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		header := &tar.Header{
			Name: e.name,
			Mode: int64(e.perm),
			Size: int64(len(data)),
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tw.Write(data); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// Restore extracts an archive. It refuses to overwrite an existing config
// unless force is true.
func Restore(r io.Reader, paths config.Paths, force bool) error {
	if !force {
		if _, err := os.Stat(paths.ConfigFile()); err == nil {
			return fmt.Errorf("ya existe una instalación; usa --force para sobrescribir")
		}
	}

	allowed := make(map[string]entry)
	for _, e := range entries(paths) {
		allowed[e.name] = e
	}

	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("archivo inválido: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	if err := paths.Ensure(); err != nil {
		return err
	}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.ToSlash(strings.TrimPrefix(header.Name, "./"))
		e, ok := allowed[name]
		if !ok {
			return fmt.Errorf("entrada no permitida en el archivo: %s", header.Name)
		}
		if header.Size > 10<<20 {
			return fmt.Errorf("entrada demasiado grande: %s", name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, 10<<20))
		if err != nil {
			return err
		}
		if err := fsutil.WriteFile(e.path, data, e.perm); err != nil {
			return err
		}
	}
	return nil
}
