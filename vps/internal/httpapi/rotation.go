package httpapi

import (
	"context"
	"log"
	"net/http"
	"time"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/service"
	"umbrel-tunnel/internal/state"
)

// Keep the durable store on the old key until the new tunnel confirms. A daemon
// restart also restores the old key through startup reconciliation.
type peerRotation struct {
	id, peerID, publicKey string
	switched, committed   bool
}

const rotationDelay = 2 * time.Second
const rotationWindow = 60 * time.Second

func (s *Server) rotationBusy(w http.ResponseWriter) bool {
	if s.rotation != nil && !s.rotation.committed {
		writeError(w, http.StatusConflict, "rotación WireGuard pendiente; reintenta en un minuto")
		return true
	}
	return false
}

func (s *Server) prepareRotation(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotationBusy(w) {
		return
	}
	var req peerUpdateRequest
	if err := decode(w, r, &req); err != nil || !service.ValidPubKey(req.PublicKey) {
		writeError(w, http.StatusBadRequest, "clave pública inválida")
		return
	}
	peer, ok := s.svc.Store.PeerByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "peer no encontrado")
		return
	}
	for _, p := range s.svc.Store.Peers() {
		if p.PublicKey == req.PublicKey {
			writeError(w, http.StatusConflict, "la clave pública ya está en uso")
			return
		}
	}
	id, err := config.GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	rotation := &peerRotation{id: id, peerID: peer.ID, publicKey: req.PublicKey}
	s.rotation = rotation
	// The old tunnel must carry this response before either side switches keys.
	writeJSON(w, http.StatusAccepted, map[string]any{"rotation_id": id, "switch_after": 2, "rollback_after": 60})
	go func() {
		time.Sleep(rotationDelay)
		s.switchRotation(rotation)
		time.Sleep(rotationWindow)
		for !s.expireRotation(rotation) {
			time.Sleep(5 * time.Second)
		}
	}()
}

func (s *Server) switchRotation(rotation *peerRotation) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotation != rotation || rotation.committed {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	peers := s.svc.Store.Peers()
	for i := range peers {
		if peers[i].ID == rotation.peerID {
			peers[i].PublicKey = rotation.publicKey
		}
	}
	private, err := s.svc.ServerPrivateKey()
	if err == nil {
		err = s.svc.WG.WriteConfigs(private, peers)
	}
	if err == nil {
		err = s.svc.WG.Sync(ctx)
	}
	if err != nil {
		log.Printf("WireGuard rotation: %v", err)
		if s.svc.ReloadPeers(ctx) == nil {
			s.rotation = nil
		}
		return
	}
	rotation.switched = true
}

func (s *Server) expireRotation(rotation *peerRotation) bool {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotation != rotation || rotation.committed {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.svc.ReloadPeers(ctx); err != nil {
		log.Printf("WireGuard rotation rollback: %v", err)
		return false
	}
	s.rotation = nil
	return true
}

func (s *Server) confirmRotation(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	var req struct {
		ID string `json:"rotation_id"`
	}
	if err := decode(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido")
		return
	}
	rotation := s.rotation
	if rotation == nil || rotation.peerID != r.PathValue("id") || rotation.id != req.ID {
		writeError(w, http.StatusConflict, "rotación no encontrada o caducada")
		return
	}
	if !rotation.switched {
		writeError(w, http.StatusConflict, "rotación todavía pendiente")
		return
	}
	if !rotation.committed {
		before, _ := s.svc.Store.PeerByID(rotation.peerID)
		_, err := s.svc.Store.UpdatePeer(rotation.peerID, func(p *state.Peer) error { p.PublicKey = rotation.publicKey; return nil })
		if err != nil {
			// Store updates its in-memory copy before writing. Restore it too,
			// otherwise the watchdog would "roll back" to the uncommitted key.
			_, _ = s.svc.Store.UpdatePeer(rotation.peerID, func(p *state.Peer) error { p.PublicKey = before.PublicKey; return nil })
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		rotation.committed = true
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
