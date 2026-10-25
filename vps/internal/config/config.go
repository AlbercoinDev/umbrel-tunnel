// Package config holds runtime configuration and well-known paths.
package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"tunnel-wg/internal/fsutil"
)

// Paths are the directories used by tunnel-wg. They can be overridden with
// environment variables, which makes integration tests possible.
type Paths struct {
	Etc       string
	State     string
	WireGuard string
	Run       string
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// DefaultPaths returns the production paths (or test overrides).
func DefaultPaths() Paths {
	return Paths{
		Etc:       envOr("TUNNEL_WG_ETC", "/etc/tunnel-wg"),
		State:     envOr("TUNNEL_WG_STATE", "/var/lib/tunnel-wg"),
		WireGuard: envOr("TUNNEL_WG_WIREGUARD", "/etc/wireguard"),
		Run:       envOr("TUNNEL_WG_RUN", "/run/tunnel-wg"),
	}
}

func (p Paths) ConfigFile() string    { return filepath.Join(p.Etc, "config.json") }
func (p Paths) TokenFile() string     { return filepath.Join(p.Etc, "token") }
func (p Paths) ClientKeyFile() string { return filepath.Join(p.Etc, "umbrel.key") }
func (p Paths) ServerKeyFile() string { return filepath.Join(p.Etc, "server.key") }
func (p Paths) ServerPubFile() string { return filepath.Join(p.Etc, "server.pub") }
func (p Paths) RulesFile() string     { return filepath.Join(p.Etc, "rules.nft") }
func (p Paths) PeersFile() string     { return filepath.Join(p.State, "peers.json") }
func (p Paths) ForwardsFile() string  { return filepath.Join(p.State, "forwards.json") }
func (p Paths) SyncConfFile() string  { return filepath.Join(p.Run, "wg0.sync.conf") }
func (p Paths) WGConfFile() string    { return filepath.Join(p.WireGuard, "wg0.conf") }

// Ensure creates all directories with restrictive permissions.
func (p Paths) Ensure() error {
	for _, d := range []struct {
		path string
		perm os.FileMode
	}{
		{p.Etc, 0o700},
		{p.State, 0o700},
		{p.WireGuard, 0o700},
		{p.Run, 0o755},
	} {
		if err := os.MkdirAll(d.path, d.perm); err != nil {
			return fmt.Errorf("crear %s: %w", d.path, err)
		}
	}
	return nil
}

// Config is the persisted server configuration (no secrets).
type Config struct {
	Version   string `json:"version"`
	APIListen string `json:"api_listen"`
	PublicAPI bool   `json:"public_api"`
	Interface string `json:"interface"`
	WGPort    int    `json:"wg_port"`
	Subnet    string `json:"subnet"`
	ServerIP  string `json:"server_ip"`
	UmbrelIP  string `json:"umbrel_ip"`
	Endpoint  string `json:"endpoint"`
	MTU       int    `json:"mtu"`
}

// Default returns a sane configuration.
func Default() Config {
	return Config{
		Version:   "1",
		APIListen: "10.0.0.1:8080",
		PublicAPI: false,
		Interface: "wg0",
		WGPort:    51820,
		Subnet:    "10.0.0.0/24",
		ServerIP:  "10.0.0.1",
		UmbrelIP:  "10.0.0.2",
		MTU:       1420,
	}
}

func (c *Config) applyDefaults() {
	def := Default()
	if c.APIListen == "" {
		c.APIListen = def.APIListen
	}
	if c.Interface == "" {
		c.Interface = def.Interface
	}
	if c.WGPort == 0 {
		c.WGPort = def.WGPort
	}
	if c.Subnet == "" {
		c.Subnet = def.Subnet
	}
	if c.ServerIP == "" {
		c.ServerIP = def.ServerIP
	}
	if c.UmbrelIP == "" {
		c.UmbrelIP = def.UmbrelIP
	}
	if c.MTU == 0 {
		c.MTU = def.MTU
	}
	if c.Version == "" {
		c.Version = def.Version
	}
}

// Load reads and validates the configuration file.
func Load(paths Paths) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(paths.ConfigFile())
	if err != nil {
		return Config{}, fmt.Errorf("leer configuración: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("configuración inválida: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Save writes the configuration atomically.
func (c Config) Save(paths Paths) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return fsutil.WriteFile(paths.ConfigFile(), data, 0o600)
}

// Validate checks the configuration.
func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.APIListen); err != nil {
		return fmt.Errorf("api_listen inválido (%q): %w", c.APIListen, err)
	}
	if c.Interface == "" || strings.ContainsAny(c.Interface, " /\\") {
		return fmt.Errorf("interfaz inválida: %q", c.Interface)
	}
	if c.WGPort < 1 || c.WGPort > 65535 {
		return fmt.Errorf("wg_port fuera de rango: %d", c.WGPort)
	}
	_, network, err := net.ParseCIDR(c.Subnet)
	if err != nil {
		return fmt.Errorf("subnet inválida: %w", err)
	}
	server := net.ParseIP(c.ServerIP)
	if server == nil || !network.Contains(server) {
		return fmt.Errorf("server_ip %q no pertenece a %s", c.ServerIP, c.Subnet)
	}
	umbrel := net.ParseIP(c.UmbrelIP)
	if umbrel == nil || !network.Contains(umbrel) {
		return fmt.Errorf("umbrel_ip %q no pertenece a %s", c.UmbrelIP, c.Subnet)
	}
	if server.Equal(umbrel) {
		return fmt.Errorf("server_ip y umbrel_ip deben ser distintos")
	}
	if c.MTU < 576 || c.MTU > 1500 {
		return fmt.Errorf("mtu fuera de rango: %d", c.MTU)
	}
	return nil
}

// ParseAPIHostPort returns the host and port of APIListen.
func (c Config) ParseAPIHostPort() (string, int, error) {
	host, portStr, err := net.SplitHostPort(c.APIListen)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

// LoadToken reads the API token.
func (p Paths) LoadToken() (string, error) {
	data, err := os.ReadFile(p.TokenFile())
	if err != nil {
		return "", fmt.Errorf("leer token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	if token == "" {
		return "", fmt.Errorf("token vacío")
	}
	return token, nil
}

// SaveToken stores the API token with 0600 permissions.
func (p Paths) SaveToken(token string) error {
	return fsutil.WriteString(p.TokenFile(), token+"\n", 0o600)
}

// GenerateToken returns 32 random bytes encoded as hex (64 chars).
func GenerateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generar token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// DetectPublicIP asks a few well-known services for the public IPv4 address.
func DetectPublicIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	var lastErr error
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			lastErr = err
			continue
		}
		req.Header.Set("User-Agent", "tunnel-wg")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
		_ = resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(string(body)))
		if ip != nil && ip.To4() != nil {
			return ip.String(), nil
		}
		lastErr = fmt.Errorf("%s devolvió %q", endpoint, strings.TrimSpace(string(body)))
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("sin respuesta")
	}
	return "", fmt.Errorf("no se pudo detectar la IP pública: %w", lastErr)
}
