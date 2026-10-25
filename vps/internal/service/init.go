package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"tunnel-wg/internal/config"
	"tunnel-wg/internal/execx"
	"tunnel-wg/internal/fsutil"
	"tunnel-wg/internal/pair"
	"tunnel-wg/internal/state"
)

// InitOptions controls `tunnel-wg init`.
type InitOptions struct {
	Endpoint     string
	Token        string
	APIListen    string
	APIPort      int
	Subnet       string
	ServerIP     string
	UmbrelIP     string
	UmbrelPubKey string
	WGPort       int
	MTU          int
	PublicAPI    bool
	Force        bool
}

// ValidPubKey reports whether s looks like a WireGuard public key.
func ValidPubKey(s string) bool {
	if len(s) != 44 || !strings.HasSuffix(s, "=") {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// Initialize creates or adopts the server configuration. It is idempotent:
// running it again keeps the existing token, keys and peers.
func Initialize(ctx context.Context, paths config.Paths, run execx.Runner, opts InitOptions) (*Service, pair.Pairing, error) {
	if err := paths.Ensure(); err != nil {
		return nil, pair.Pairing{}, err
	}

	_, statErr := os.Stat(paths.ConfigFile())
	exists := statErr == nil

	var svc *Service
	if exists && !opts.Force {
		loaded, err := Open(paths, run)
		if err != nil {
			return nil, pair.Pairing{}, err
		}
		svc = loaded
	} else {
		cfg, err := buildConfig(ctx, opts)
		if err != nil {
			return nil, pair.Pairing{}, err
		}
		if err := cfg.Save(paths); err != nil {
			return nil, pair.Pairing{}, err
		}
		loaded, err := Open(paths, run)
		if err != nil {
			return nil, pair.Pairing{}, err
		}
		svc = loaded
	}

	if err := ensureSecrets(ctx, svc, opts); err != nil {
		return nil, pair.Pairing{}, err
	}
	if err := svc.ReloadPeers(ctx); err != nil {
		return nil, pair.Pairing{}, err
	}
	if err := svc.ReloadForwards(ctx); err != nil {
		return nil, pair.Pairing{}, err
	}

	p, err := svc.Pairing()
	if err != nil {
		return nil, pair.Pairing{}, err
	}
	return svc, p, nil
}

func buildConfig(ctx context.Context, opts InitOptions) (config.Config, error) {
	cfg := config.Default()

	if opts.Endpoint != "" {
		cfg.Endpoint = strings.TrimSpace(opts.Endpoint)
	} else {
		ip, err := config.DetectPublicIP(ctx)
		if err != nil {
			return config.Config{}, fmt.Errorf("%w (usa --endpoint)", err)
		}
		cfg.Endpoint = ip
	}
	if opts.Subnet != "" {
		cfg.Subnet = opts.Subnet
	}
	if opts.ServerIP != "" {
		cfg.ServerIP = opts.ServerIP
	}
	if opts.UmbrelIP != "" {
		cfg.UmbrelIP = opts.UmbrelIP
	}
	if opts.WGPort != 0 {
		cfg.WGPort = opts.WGPort
	}
	if opts.MTU != 0 {
		cfg.MTU = opts.MTU
	}
	cfg.PublicAPI = opts.PublicAPI

	if opts.APIListen != "" {
		cfg.APIListen = opts.APIListen
	} else if opts.APIPort != 0 || opts.PublicAPI {
		host := cfg.ServerIP
		if opts.PublicAPI {
			host = "0.0.0.0"
		}
		port := opts.APIPort
		if port == 0 {
			// Keep the default API port when only --public-api is given.
			_, defaultPort, err := cfg.ParseAPIHostPort()
			if err != nil {
				defaultPort = 8080
			}
			port = defaultPort
		}
		cfg.APIListen = net.JoinHostPort(host, strconv.Itoa(port))
	}

	if err := cfg.Validate(); err != nil {
		return config.Config{}, err
	}
	return cfg, nil
}

func ensureSecrets(ctx context.Context, svc *Service, opts InitOptions) error {
	// API token.
	if _, err := svc.Paths.LoadToken(); err != nil {
		token := strings.TrimSpace(opts.Token)
		if token == "" {
			generated, err := config.GenerateToken()
			if err != nil {
				return err
			}
			token = generated
		}
		if err := svc.Paths.SaveToken(token); err != nil {
			return err
		}
	} else if opts.Token != "" {
		if err := svc.Paths.SaveToken(strings.TrimSpace(opts.Token)); err != nil {
			return err
		}
	}

	// Server keypair.
	if _, err := svc.ServerPrivateKey(); err != nil {
		priv, err := svc.WG.GenKey(ctx)
		if err != nil {
			return fmt.Errorf("generar clave del servidor: %w", err)
		}
		pub, err := svc.WG.PubKey(ctx, priv)
		if err != nil {
			return fmt.Errorf("derivar clave pública del servidor: %w", err)
		}
		if err := fsutil.WriteString(svc.Paths.ServerKeyFile(), priv+"\n", 0o600); err != nil {
			return err
		}
		if err := fsutil.WriteString(svc.Paths.ServerPubFile(), pub+"\n", 0o600); err != nil {
			return err
		}
	}

	// Umbrel client keypair (not generated in manual mode).
	clientKey, keyErr := svc.ClientPrivateKey()
	hasClientKey := keyErr == nil && clientKey != ""
	manual := strings.TrimSpace(opts.UmbrelPubKey) != ""
	if !hasClientKey && !manual {
		if _, ok := svc.Store.PeerByIP(svc.Cfg.UmbrelIP); !ok {
			priv, err := svc.WG.GenKey(ctx)
			if err != nil {
				return fmt.Errorf("generar clave del cliente: %w", err)
			}
			if err := fsutil.WriteString(svc.Paths.ClientKeyFile(), priv+"\n", 0o600); err != nil {
				return err
			}
			clientKey = priv
			hasClientKey = true
		}
	}

	// Ensure the Umbrel peer exists and matches the expected public key.
	var wantPub string
	switch {
	case manual:
		wantPub = strings.TrimSpace(opts.UmbrelPubKey)
		if !ValidPubKey(wantPub) {
			return fmt.Errorf("clave pública de Umbrel inválida")
		}
	case hasClientKey:
		pub, err := svc.WG.PubKey(ctx, clientKey)
		if err != nil {
			return fmt.Errorf("derivar clave pública del cliente: %w", err)
		}
		wantPub = pub
	}

	if wantPub != "" {
		if peer, ok := svc.Store.PeerByIP(svc.Cfg.UmbrelIP); ok {
			if peer.PublicKey != wantPub {
				if !opts.Force && !manual {
					return fmt.Errorf("el peer %s ya existe con otra clave pública", svc.Cfg.UmbrelIP)
				}
				if _, err := svc.Store.UpdatePeer(peer.ID, func(p *state.Peer) error {
					p.PublicKey = wantPub
					return nil
				}); err != nil {
					return err
				}
			}
		} else {
			if err := svc.Store.AddPeer(state.Peer{
				Name:      "umbrel",
				PublicKey: wantPub,
				AllowedIP: svc.Cfg.UmbrelIP,
			}); err != nil {
				return err
			}
		}
	}

	return nil
}
