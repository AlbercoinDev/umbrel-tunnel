// Package wireguard generates configs and talks to the WireGuard tools.
package wireguard

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/execx"
	"tunnel-wg/internal/fsutil"
	"tunnel-wg/internal/state"
)

// Manager owns the server-side WireGuard configuration.
type Manager struct {
	paths config.Paths
	cfg   config.Config
	run   execx.Runner
}

// New creates a Manager.
func New(paths config.Paths, cfg config.Config, run execx.Runner) *Manager {
	return &Manager{paths: paths, cfg: cfg, run: run}
}

// GenKey generates a WireGuard private key.
func (m *Manager) GenKey(ctx context.Context) (string, error) {
	out, err := m.run.Run(ctx, "wg", "genkey")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(out))
	if key == "" {
		return "", fmt.Errorf("wg genkey devolvió una clave vacía")
	}
	return key, nil
}

// PubKey derives the public key from a private key.
func (m *Manager) PubKey(ctx context.Context, privateKey string) (string, error) {
	out, err := m.run.RunInput(ctx, []byte(privateKey+"\n"), "wg", "pubkey")
	if err != nil {
		return "", err
	}
	key := strings.TrimSpace(string(out))
	if key == "" {
		return "", fmt.Errorf("wg pubkey devolvió una clave vacía")
	}
	return key, nil
}

// AddressCIDR returns the peer address with the tunnel prefix length.
func (m *Manager) AddressCIDR(ip string) string {
	_, network, err := net.ParseCIDR(m.cfg.Subnet)
	if err != nil {
		return ip + "/24"
	}
	ones, _ := network.Mask.Size()
	return fmt.Sprintf("%s/%d", ip, ones)
}

// ServerConfig renders /etc/wireguard/wg0.conf.
func (m *Manager) ServerConfig(privateKey string, peers []state.Peer) string {
	var b strings.Builder
	b.WriteString("# Managed by tunnel-wg - no editar a mano\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", m.AddressCIDR(m.cfg.ServerIP))
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", m.cfg.WGPort)
	b.WriteString("SaveConfig = false\n")
	fmt.Fprintf(&b, "MTU = %d\n", m.cfg.MTU)
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# %s\n", sanitizeComment(p.Name))
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", p.AllowedIP)
	}
	return b.String()
}

// SyncConfig renders the stripped config accepted by `wg syncconf`.
func (m *Manager) SyncConfig(privateKey string, peers []state.Peer) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", privateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", m.cfg.WGPort)
	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		fmt.Fprintf(&b, "AllowedIPs = %s/32\n", p.AllowedIP)
	}
	return b.String()
}

func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// WriteConfigs persists wg0.conf and the stripped config used by syncconf.
func (m *Manager) WriteConfigs(privateKey string, peers []state.Peer) error {
	if err := fsutil.WriteString(m.paths.WGConfFile(), m.ServerConfig(privateKey, peers), 0o600); err != nil {
		return err
	}
	return fsutil.WriteString(m.paths.SyncConfFile(), m.SyncConfig(privateKey, peers), 0o600)
}

// InterfaceUp reports whether the WireGuard interface exists.
func (m *Manager) InterfaceUp(ctx context.Context) bool {
	_, err := m.run.Run(ctx, "wg", "show", m.cfg.Interface)
	return err == nil
}

// Sync applies peers without tearing down the interface.
func (m *Manager) Sync(ctx context.Context) error {
	if !m.InterfaceUp(ctx) {
		return nil
	}
	_, err := m.run.Run(ctx, "wg", "syncconf", m.cfg.Interface, m.paths.SyncConfFile())
	return err
}

// Up brings the interface up with wg-quick.
func (m *Manager) Up(ctx context.Context) error {
	_, err := m.run.Run(ctx, "wg-quick", "up", m.cfg.Interface)
	return err
}

// Down brings the interface down.
func (m *Manager) Down(ctx context.Context) error {
	_, err := m.run.Run(ctx, "wg-quick", "down", m.cfg.Interface)
	return err
}

// PeerStatus is one row of `wg show dump`.
type PeerStatus struct {
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint"`
	AllowedIPs      string `json:"allowed_ips"`
	LatestHandshake int64  `json:"latest_handshake"`
	Rx              int64  `json:"rx"`
	Tx              int64  `json:"tx"`
	Connected       bool   `json:"connected"`
}

// Status is the parsed output of `wg show`.
type Status struct {
	Running    bool         `json:"running"`
	Interface  string       `json:"interface"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	Peers      []PeerStatus `json:"peers"`
}

// Status parses `wg show <iface> dump`.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	st := Status{Interface: m.cfg.Interface}
	out, err := m.run.Run(ctx, "wg", "show", m.cfg.Interface, "dump")
	if err != nil {
		return st, err
	}
	st.Running = true
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return st, nil
	}
	iface := strings.Split(lines[0], "\t")
	if len(iface) >= 3 {
		st.PublicKey = iface[1]
		st.ListenPort, _ = strconv.Atoi(iface[2])
	}
	now := time.Now().Unix()
	for _, line := range lines[1:] {
		parts := strings.Split(line, "\t")
		if len(parts) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(parts[4], 10, 64)
		rx, _ := strconv.ParseInt(parts[5], 10, 64)
		tx, _ := strconv.ParseInt(parts[6], 10, 64)
		st.Peers = append(st.Peers, PeerStatus{
			PublicKey:       parts[0],
			Endpoint:        parts[2],
			AllowedIPs:      parts[3],
			LatestHandshake: handshake,
			Rx:              rx,
			Tx:              tx,
			Connected:       handshake > 0 && now-handshake < 180,
		})
	}
	return st, nil
}

// ClientConfig renders the config that the Umbrel peer must use.
func (m *Manager) ClientConfig(clientPrivateKey, serverPublicKey, peerIP string) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", clientPrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", m.AddressCIDR(peerIP))
	fmt.Fprintf(&b, "MTU = %d\n", m.cfg.MTU)
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", m.cfg.Endpoint, m.cfg.WGPort)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", m.cfg.Subnet)
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
