// Package state persists peers and forwarded ports as small JSON files.
package state

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/fsutil"
)

// Peer is a WireGuard client allowed to use the tunnel.
type Peer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	AllowedIP string    `json:"allowed_ip"`
	Endpoint  string    `json:"endpoint,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Forward is a public TCP/UDP port redirected to a peer.
type Forward struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicPort int       `json:"public_port"`
	TargetIP   string    `json:"target_ip"`
	TargetPort int       `json:"target_port"`
	Protocol   string    `json:"protocol"`
	ManagedBy  string    `json:"managed_by,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
}

// Store is a concurrency-safe in-memory view of the JSON files.
type Store struct {
	mu       sync.RWMutex
	paths    config.Paths
	peers    []Peer
	forwards []Forward
}

// NewID returns a short random identifier.
func NewID() string {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

type peerJSON struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	PublicKey string     `json:"public_key"`
	AllowedIP string     `json:"allowed_ip"`
	Endpoint  string     `json:"endpoint"`
	CreatedAt *time.Time `json:"created_at"`
}

type forwardJSON struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	PublicPort int        `json:"public_port"`
	Dport      int        `json:"dport"`
	TargetIP   string     `json:"target_ip"`
	TargetPort int        `json:"target_port"`
	Protocol   string     `json:"protocol"`
	ManagedBy  string     `json:"managed_by"`
	Enabled    *bool      `json:"enabled"`
	CreatedAt  *time.Time `json:"created_at"`
}

// Open loads the state files (migrating legacy fields).
func Open(paths config.Paths) (*Store, error) {
	s := &Store{paths: paths}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func readList(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return raw, nil
}

func (s *Store) load() error {
	rawPeers, err := readList(s.paths.PeersFile())
	if err != nil {
		return err
	}
	for _, item := range rawPeers {
		var p peerJSON
		if err := json.Unmarshal(item, &p); err != nil {
			return fmt.Errorf("peer inválido: %w", err)
		}
		created := time.Now().UTC()
		if p.CreatedAt != nil {
			created = *p.CreatedAt
		}
		s.peers = append(s.peers, Peer{
			ID:        p.ID,
			Name:      p.Name,
			PublicKey: p.PublicKey,
			AllowedIP: p.AllowedIP,
			Endpoint:  p.Endpoint,
			CreatedAt: created,
		})
	}

	rawForwards, err := readList(s.paths.ForwardsFile())
	if err != nil {
		return err
	}
	for _, item := range rawForwards {
		var f forwardJSON
		if err := json.Unmarshal(item, &f); err != nil {
			return fmt.Errorf("forward inválido: %w", err)
		}
		public := f.PublicPort
		if public == 0 {
			public = f.Dport
		}
		enabled := true
		if f.Enabled != nil {
			enabled = *f.Enabled
		}
		protocol := f.Protocol
		if protocol == "" {
			protocol = "tcp"
		}
		created := time.Now().UTC()
		if f.CreatedAt != nil {
			created = *f.CreatedAt
		}
		s.forwards = append(s.forwards, Forward{
			ID:         f.ID,
			Name:       f.Name,
			PublicPort: public,
			TargetIP:   f.TargetIP,
			TargetPort: f.TargetPort,
			Protocol:   protocol,
			ManagedBy:  f.ManagedBy,
			Enabled:    enabled,
			CreatedAt:  created,
		})
	}
	return nil
}

func (s *Store) saveLocked() error {
	peers, err := json.MarshalIndent(s.peers, "", "  ")
	if err != nil {
		return err
	}
	if s.peers == nil {
		peers = []byte("[]")
	}
	if err := fsutil.WriteFile(s.paths.PeersFile(), append(peers, '\n'), 0o600); err != nil {
		return err
	}

	forwards, err := json.MarshalIndent(s.forwards, "", "  ")
	if err != nil {
		return err
	}
	if s.forwards == nil {
		forwards = []byte("[]")
	}
	if err := fsutil.WriteFile(s.paths.ForwardsFile(), append(forwards, '\n'), 0o600); err != nil {
		return err
	}
	return nil
}

// Save persists the current state.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

// Peers returns a copy of the peer list.
func (s *Store) Peers() []Peer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Peer(nil), s.peers...)
}

// Forwards returns a copy of the forward list.
func (s *Store) Forwards() []Forward {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Forward(nil), s.forwards...)
}

// PeerByPublicKey finds a peer by its WireGuard public key.
func (s *Store) PeerByPublicKey(key string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.peers {
		if p.PublicKey == key {
			return p, true
		}
	}
	return Peer{}, false
}

// PeerByIP finds a peer by its allowed IP.
func (s *Store) PeerByIP(ip string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.peers {
		if p.AllowedIP == ip {
			return p, true
		}
	}
	return Peer{}, false
}

// PeerByID finds a peer by its identifier.
func (s *Store) PeerByID(id string) (Peer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, p := range s.peers {
		if p.ID == id {
			return p, true
		}
	}
	return Peer{}, false
}

// AddPeer validates uniqueness, stores and persists the peer.
func (s *Store) AddPeer(p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.peers {
		if existing.PublicKey == p.PublicKey {
			return fmt.Errorf("ya existe un peer con esa clave pública")
		}
		if existing.AllowedIP == p.AllowedIP {
			return fmt.Errorf("ya existe un peer con la IP %s", p.AllowedIP)
		}
	}
	if p.ID == "" {
		p.ID = NewID()
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now().UTC()
	}
	s.peers = append(s.peers, p)
	return s.saveLocked()
}

// RemovePeer deletes a peer by ID.
func (s *Store) RemovePeer(id string) (Peer, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, p := range s.peers {
		if p.ID == id {
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			return p, true, s.saveLocked()
		}
	}
	return Peer{}, false, nil
}

// UpdatePeer replaces the public key and/or endpoint of a peer.
func (s *Store) UpdatePeer(id string, fn func(*Peer) error) (Peer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.peers {
		if s.peers[i].ID == id {
			updated := s.peers[i]
			if err := fn(&updated); err != nil {
				return Peer{}, err
			}
			for j := range s.peers {
				if j != i && s.peers[j].PublicKey == updated.PublicKey {
					return Peer{}, fmt.Errorf("ya existe un peer con esa clave pública")
				}
				if j != i && s.peers[j].AllowedIP == updated.AllowedIP {
					return Peer{}, fmt.Errorf("ya existe un peer con la IP %s", updated.AllowedIP)
				}
			}
			s.peers[i] = updated
			if err := s.saveLocked(); err != nil {
				return Peer{}, err
			}
			return s.peers[i], nil
		}
	}
	return Peer{}, fmt.Errorf("peer %s no encontrado", id)
}

// AddForward validates uniqueness, stores and persists the forward.
// ReservedPublicPorts are never DNATed: 22 is the VPS SSH port and
// redirecting it would lock the administrator out of the server.
var ReservedPublicPorts = map[int]string{22: "SSH del VPS"}

func (s *Store) AddForward(f Forward) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.Protocol == "" {
		f.Protocol = "tcp"
	}
	if what, ok := ReservedPublicPorts[f.PublicPort]; ok && f.Protocol == "tcp" {
		return fmt.Errorf("el puerto público %d está reservado para el %s", f.PublicPort, what)
	}
	for _, existing := range s.forwards {
		if existing.PublicPort == f.PublicPort && existing.Protocol == f.Protocol {
			return fmt.Errorf("el puerto %d/%s ya está en uso", f.PublicPort, f.Protocol)
		}
	}
	if f.ID == "" {
		f.ID = NewID()
	}
	if f.Protocol == "" {
		f.Protocol = "tcp"
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	s.forwards = append(s.forwards, f)
	return s.saveLocked()
}

// UpdateForward mutates a forward by ID.
func (s *Store) UpdateForward(id string, fn func(*Forward) error) (Forward, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.forwards {
		if s.forwards[i].ID == id {
			updated := s.forwards[i]
			if err := fn(&updated); err != nil {
				return Forward{}, err
			}
			if what, ok := ReservedPublicPorts[updated.PublicPort]; ok && updated.Protocol != "udp" {
				return Forward{}, fmt.Errorf("el puerto público %d está reservado para el %s", updated.PublicPort, what)
			}
			for j := range s.forwards {
				if j == i {
					continue
				}
				if s.forwards[j].PublicPort == updated.PublicPort &&
					s.forwards[j].Protocol == updated.Protocol {
					return Forward{}, fmt.Errorf("el puerto %d/%s ya está en uso", updated.PublicPort, updated.Protocol)
				}
			}
			s.forwards[i] = updated
			if err := s.saveLocked(); err != nil {
				return Forward{}, err
			}
			return s.forwards[i], nil
		}
	}
	return Forward{}, fmt.Errorf("forward %s no encontrado", id)
}

// RemoveForward deletes a forward by ID.
func (s *Store) RemoveForward(id string) (Forward, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, f := range s.forwards {
		if f.ID == id {
			s.forwards = append(s.forwards[:i], s.forwards[i+1:]...)
			return f, true, s.saveLocked()
		}
	}
	return Forward{}, false, nil
}
