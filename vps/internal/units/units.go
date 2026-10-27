// Package units carries the systemd and kernel files inside the binary so a
// self-update can refresh them without downloading the release tarball.
package units

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed files/*
var files embed.FS

// File is a packaged file and its destination below the installation root.
type File struct {
	Name string
	Path string
}

// Files lists everything the installer and the updater must keep in sync.
var Files = []File{
	{Name: "umbrel-tunnel.service", Path: "etc/systemd/system/umbrel-tunnel.service"},
	{Name: "umbrel-tunnel-firewall.service", Path: "etc/systemd/system/umbrel-tunnel-firewall.service"},
	{Name: "umbrel-tunnel.conf", Path: "etc/tmpfiles.d/umbrel-tunnel.conf"},
	{Name: "90-umbrel-tunnel.conf", Path: "etc/sysctl.d/90-umbrel-tunnel.conf"},
}

// Install writes every packaged file below root. root is "/" on a real host.
func Install(root string) error {
	for _, file := range Files {
		data, err := files.ReadFile("files/" + file.Name)
		if err != nil {
			return fmt.Errorf("leer %s: %w", file.Name, err)
		}
		target := filepath.Join(root, file.Path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("crear %s: %w", filepath.Dir(target), err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return fmt.Errorf("escribir %s: %w", target, err)
		}
	}
	return nil
}

// Content returns one packaged file, used by tests and diagnostics.
func Content(name string) ([]byte, error) {
	return files.ReadFile("files/" + name)
}
