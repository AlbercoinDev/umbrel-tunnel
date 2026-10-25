// Package service wires configuration, state and system tools together.
package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/firewall"
	"umbrel-tunnel/internal/pair"
	"umbrel-tunnel/internal/state"
	"umbrel-tunnel/internal/wireguard"
)

// Service bundles the managers used by the CLI and the HTTP API.
type Service struct {
	Paths config.Paths
	Cfg   config.Config
	Store *state.Store
	WG    *wireguard.Manager
	FW    *firewall.Manager
	Run   execx.Runner
}

// Open loads configuration and state.
func Open(paths config.Paths, run execx.Runner) (*Service, error) {
	cfg, err := config.Load(paths)
	if err != nil {
		return nil, err
	}
	store, err := state.Open(paths)
	if err != nil {
		return nil, err
	}
	return &Service{
		Paths: paths,
		Cfg:   cfg,
		Store: store,
		WG:    wireguard.New(paths, cfg, run),
		FW:    firewall.New(paths, cfg, run),
		Run:   run,
	}, nil
}

// ServerPrivateKey reads the server private key.
func (s *Service) ServerPrivateKey() (string, error) {
	data, err := os.ReadFile(s.Paths.ServerKeyFile())
	if err != nil {
		return "", fmt.Errorf("leer clave del servidor: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("clave del servidor vacía")
	}
	return key, nil
}

// ServerPublicKey reads the server public key.
func (s *Service) ServerPublicKey() (string, error) {
	data, err := os.ReadFile(s.Paths.ServerPubFile())
	if err != nil {
		return "", fmt.Errorf("leer clave pública del servidor: %w", err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("clave pública del servidor vacía")
	}
	return key, nil
}

// ClientPrivateKey reads the Umbrel client private key (may not exist in
// manual pairing mode).
func (s *Service) ClientPrivateKey() (string, error) {
	data, err := os.ReadFile(s.Paths.ClientKeyFile())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReloadPeers regenerates the WireGuard config and applies it with syncconf.
func (s *Service) ReloadPeers(ctx context.Context) error {
	priv, err := s.ServerPrivateKey()
	if err != nil {
		return err
	}
	if err := s.WG.WriteConfigs(priv, s.Store.Peers()); err != nil {
		return err
	}
	return s.WG.Sync(ctx)
}

// ReloadForwards regenerates and applies the nftables ruleset.
func (s *Service) ReloadForwards(ctx context.Context) error {
	return s.FW.Apply(ctx, s.Store.Forwards())
}

// Reconcile rewrites configs and reapplies rules (used at startup).
func (s *Service) Reconcile(ctx context.Context) error {
	if err := s.ReloadPeers(ctx); err != nil {
		return err
	}
	return s.ReloadForwards(ctx)
}

// APIURL is the URL the Umbrel app must use (always over the tunnel).
func (s *Service) APIURL() string {
	_, port, err := s.Cfg.ParseAPIHostPort()
	if err != nil {
		port = 8080
	}
	return "http://" + net.JoinHostPort(s.Cfg.ServerIP, fmt.Sprintf("%d", port))
}

// Pairing builds the ut1 payload for the Umbrel app.
func (s *Service) Pairing() (pair.Pairing, error) {
	token, err := s.Paths.LoadToken()
	if err != nil {
		return pair.Pairing{}, err
	}
	p := pair.Pairing{
		V:        1,
		API:      s.APIURL(),
		Token:    token,
		Endpoint: net.JoinHostPort(s.Cfg.Endpoint, fmt.Sprintf("%d", s.Cfg.WGPort)),
		UmbrelIP: s.Cfg.UmbrelIP,
	}
	if pub, err := s.ServerPublicKey(); err == nil {
		p.ServerPubKey = pub
	}

	clientKey, err := s.ClientPrivateKey()
	if err != nil || clientKey == "" {
		return p, nil
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return pair.Pairing{}, err
	}
	peer, ok := s.Store.PeerByIP(s.Cfg.UmbrelIP)
	if !ok {
		return p, nil
	}
	p.WG = s.WG.ClientConfig(clientKey, serverPub, peer.AllowedIP)
	return p, nil
}

// ValidateIPInSubnet checks that ip belongs to the tunnel subnet.
func (s *Service) ValidateIPInSubnet(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return fmt.Errorf("IP inválida: %q", ip)
	}
	_, network, err := net.ParseCIDR(s.Cfg.Subnet)
	if err != nil {
		return err
	}
	if !network.Contains(parsed) {
		return fmt.Errorf("la IP %s no pertenece a %s", ip, s.Cfg.Subnet)
	}
	if parsed.Equal(net.ParseIP(s.Cfg.ServerIP)) {
		return fmt.Errorf("la IP %s está reservada para el servidor", ip)
	}
	return nil
}
