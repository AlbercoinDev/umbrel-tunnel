// Package httpapi exposes the control plane over HTTP.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/edge"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/pair"
	"umbrel-tunnel/internal/service"
	"umbrel-tunnel/internal/state"
	"umbrel-tunnel/internal/webui"
	"umbrel-tunnel/internal/wireguard"
)

// Server is the HTTP control plane.
type Server struct {
	svc     *service.Service
	version string
	started time.Time
	run     execx.Runner

	mu        sync.Mutex
	statusAt  time.Time
	status    wireguard.Status
	forwardMu sync.Mutex
	rotation  *peerRotation // protected by forwardMu
}

// New creates a Server.
func New(svc *service.Service, version string, run execx.Runner) *Server {
	return &Server{
		svc:     svc,
		version: version,
		started: time.Now(),
		run:     run,
	}
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /api/status", s.auth(s.statusHandler))
	mux.HandleFunc("GET /api/peers", s.auth(s.listPeers))
	mux.HandleFunc("POST /api/peers", s.auth(s.createPeer))
	mux.HandleFunc("PUT /api/peers/{id}", s.auth(s.updatePeer))
	mux.HandleFunc("POST /api/peers/{id}/rotation", s.auth(s.prepareRotation))
	mux.HandleFunc("POST /api/peers/{id}/rotation/confirm", s.auth(s.confirmRotation))
	mux.HandleFunc("DELETE /api/peers/{id}", s.auth(s.deletePeer))
	mux.HandleFunc("GET /api/peers/{id}/config", s.auth(s.peerConfig))
	mux.HandleFunc("GET /api/forwards", s.auth(s.listForwards))
	mux.HandleFunc("GET /api/certificates", s.auth(s.certificates))
	mux.HandleFunc("POST /api/certificates/retry", s.auth(s.retryCertificates))
	mux.HandleFunc("POST /api/forwards/reconcile", s.auth(s.reconcileForwards))
	mux.HandleFunc("GET /api/forwards/{id}/check", s.auth(s.checkForward))
	mux.HandleFunc("POST /api/forwards", s.auth(s.createForward))
	mux.HandleFunc("PATCH /api/forwards/{id}", s.auth(s.patchForward))
	mux.HandleFunc("DELETE /api/forwards/{id}", s.auth(s.deleteForward))
	mux.HandleFunc("POST /api/token/rotate", s.auth(s.rotateToken))
	mux.HandleFunc("GET /", s.index)
	mux.HandleFunc("GET /app.js", s.asset("app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /style.css", s.asset("style.css", "text/css; charset=utf-8"))
	return s.headers(mux)
}

func (s *Server) headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := s.svc.Paths.LoadToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "token no disponible")
			return
		}
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) ||
			subtle.ConstantTimeCompare([]byte(strings.TrimSpace(strings.TrimPrefix(header, prefix))), []byte(token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="umbrel-tunnel"`)
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"code": fmt.Sprintf("http_%d", code), "error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": s.version})
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, err := webui.FS.ReadFile("index.html")
	if err != nil {
		http.Error(w, "dashboard no disponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (s *Server) asset(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := webui.FS.ReadFile(name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(data)
	}
}

func (s *Server) wgStatus(ctx context.Context) wireguard.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.statusAt) < 2*time.Second {
		return s.status
	}
	st, _ := s.svc.WG.Status(ctx)
	s.status = st
	s.statusAt = time.Now()
	return st
}

type peerView struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	AllowedIP       string `json:"allowed_ip"`
	PublicKey       string `json:"public_key"`
	Connected       bool   `json:"connected"`
	LatestHandshake int64  `json:"latest_handshake"`
	Rx              int64  `json:"rx"`
	Tx              int64  `json:"tx"`
}

type statusResponse struct {
	Version         string           `json:"version"`
	UptimeSeconds   int64            `json:"uptime_seconds"`
	WG              wireguard.Status `json:"wg"`
	PeersTotal      int              `json:"peers_total"`
	PeersConnected  int              `json:"peers_connected"`
	ForwardsTotal   int              `json:"forwards_total"`
	ForwardsEnabled int              `json:"forwards_enabled"`
	APIListen       string           `json:"api_listen"`
	PublicAPI       bool             `json:"public_api"`
	Peers           []peerView       `json:"peers"`
}

func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	st := s.wgStatus(r.Context())
	byKey := make(map[string]wireguard.PeerStatus, len(st.Peers))
	for _, p := range st.Peers {
		byKey[p.PublicKey] = p
	}

	peers := s.svc.Store.Peers()
	views := make([]peerView, 0, len(peers))
	connected := 0
	for _, p := range peers {
		view := peerView{ID: p.ID, Name: p.Name, AllowedIP: p.AllowedIP, PublicKey: p.PublicKey}
		if rt, ok := byKey[p.PublicKey]; ok {
			view.Connected = rt.Connected
			view.LatestHandshake = rt.LatestHandshake
			view.Rx = rt.Rx
			view.Tx = rt.Tx
			if rt.Connected {
				connected++
			}
		}
		views = append(views, view)
	}

	forwards := s.svc.Store.Forwards()
	enabled := 0
	for _, f := range forwards {
		if f.Enabled {
			enabled++
		}
	}

	writeJSON(w, http.StatusOK, statusResponse{
		Version:         s.version,
		UptimeSeconds:   int64(time.Since(s.started).Seconds()),
		WG:              st,
		PeersTotal:      len(peers),
		PeersConnected:  connected,
		ForwardsTotal:   len(forwards),
		ForwardsEnabled: enabled,
		APIListen:       s.svc.Cfg.APIListen,
		PublicAPI:       s.svc.Cfg.PublicAPI,
		Peers:           views,
	})
}

type peerRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	AllowedIP string `json:"allowed_ip"`
	Endpoint  string `json:"endpoint"`
}

type peerResponse struct {
	state.Peer
	PrivateKey string `json:"private_key,omitempty"`
}

func (s *Server) listPeers(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Store.Peers())
}

func (s *Server) createPeer(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotationBusy(w) {
		return
	}
	var req peerRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.AllowedIP = strings.TrimSpace(req.AllowedIP)
	if req.Name == "" || len(req.Name) > 64 {
		writeError(w, http.StatusBadRequest, "nombre inválido")
		return
	}
	if err := s.svc.ValidateIPInSubnet(req.AllowedIP); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	var privateKey string
	if req.PublicKey == "" {
		priv, err := s.svc.WG.GenKey(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "no se pudo generar la clave: "+err.Error())
			return
		}
		pub, err := s.svc.WG.PubKey(r.Context(), priv)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "no se pudo derivar la clave pública: "+err.Error())
			return
		}
		req.PublicKey = pub
		privateKey = priv
	} else if !service.ValidPubKey(req.PublicKey) {
		writeError(w, http.StatusBadRequest, "clave pública inválida")
		return
	}

	peer := state.Peer{
		Name:      req.Name,
		PublicKey: req.PublicKey,
		AllowedIP: req.AllowedIP,
		Endpoint:  strings.TrimSpace(req.Endpoint),
	}
	if err := s.svc.Store.AddPeer(peer); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "ya existe") {
			code = http.StatusConflict
		}
		writeError(w, code, err.Error())
		return
	}
	created, _ := s.svc.Store.PeerByIP(req.AllowedIP)

	if err := s.svc.ReloadPeers(r.Context()); err != nil {
		_, _, _ = s.svc.Store.RemovePeer(created.ID)
		_ = s.svc.ReloadPeers(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar WireGuard: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, peerResponse{Peer: created, PrivateKey: privateKey})
}

type peerUpdateRequest struct {
	PublicKey string `json:"public_key"`
	Endpoint  string `json:"endpoint"`
}

// updatePeer rotates the public key of an existing peer. The Umbrel app uses
// it when it regenerates its local WireGuard keypair.
func (s *Server) updatePeer(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotationBusy(w) {
		return
	}
	id := r.PathValue("id")
	var req peerUpdateRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if !service.ValidPubKey(req.PublicKey) {
		writeError(w, http.StatusBadRequest, "clave pública inválida")
		return
	}
	old, ok := s.svc.Store.PeerByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "peer no encontrado")
		return
	}
	updated, err := s.svc.Store.UpdatePeer(id, func(p *state.Peer) error {
		p.PublicKey = req.PublicKey
		if endpoint := strings.TrimSpace(req.Endpoint); endpoint != "" {
			p.Endpoint = endpoint
		}
		return nil
	})
	if err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "no encontrado") {
			code = http.StatusNotFound
		}
		writeError(w, code, err.Error())
		return
	}
	if err := s.svc.ReloadPeers(r.Context()); err != nil {
		// Roll back the stored key if the live interface cannot be updated.
		_, _ = s.svc.Store.UpdatePeer(id, func(p *state.Peer) error {
			p.PublicKey = old.PublicKey
			p.Endpoint = old.Endpoint
			return nil
		})
		_ = s.svc.ReloadPeers(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar WireGuard: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deletePeer(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if s.rotationBusy(w) {
		return
	}
	id := r.PathValue("id")
	removed, ok, err := s.svc.Store.RemovePeer(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "peer no encontrado")
		return
	}
	if err := s.svc.ReloadPeers(r.Context()); err != nil {
		_ = s.svc.Store.AddPeer(removed)
		_ = s.svc.ReloadPeers(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar WireGuard: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) peerConfig(w http.ResponseWriter, r *http.Request) {
	peer, ok := s.svc.Store.PeerByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "peer no encontrado")
		return
	}
	clientKey, err := s.svc.ClientPrivateKey()
	if err != nil || clientKey == "" {
		writeError(w, http.StatusConflict, "no hay clave privada del cliente (modo emparejamiento manual)")
		return
	}
	derived, err := s.svc.WG.PubKey(r.Context(), clientKey)
	if err != nil || derived != peer.PublicKey {
		writeError(w, http.StatusConflict, "la clave privada heredada no corresponde a este peer; usa la CLI con --private-key-file")
		return
	}
	serverPub, err := s.svc.ServerPublicKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"config": s.svc.WG.ClientConfig(clientKey, serverPub, peer.AllowedIP),
	})
}

type forwardRequest struct {
	AcceptACMETerms bool   `json:"accept_acme_terms"`
	AccessMode      string `json:"access_mode"`
	Domain          string `json:"domain"`
	Name            string `json:"name"`
	PublicPort      int    `json:"public_port"`
	TargetIP        string `json:"target_ip"`
	TargetPort      int    `json:"target_port"`
	Protocol        string `json:"protocol"`
	ManagedBy       string `json:"managed_by"`
	Enabled         *bool  `json:"enabled"`
}

func normalizeProtocol(proto string) (string, error) {
	proto = strings.ToLower(strings.TrimSpace(proto))
	if proto == "" {
		return "tcp", nil
	}
	if proto != "tcp" && proto != "udp" {
		return "", fmt.Errorf("protocolo no soportado: %s", proto)
	}
	return proto, nil
}

func validPort(port int) bool {
	return port >= 1 && port <= 65535
}

func (s *Server) validateForward(name string, publicPort int, targetIP string, targetPort int, proto string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("port-%d", publicPort)
	}
	if len(name) > 64 {
		return "", fmt.Errorf("nombre demasiado largo")
	}
	if !validPort(publicPort) || !validPort(targetPort) {
		return "", fmt.Errorf("puerto fuera de rango")
	}
	proto, err := normalizeProtocol(proto)
	if err != nil {
		return "", err
	}
	if proto == "udp" && publicPort == s.svc.Cfg.WGPort {
		return "", fmt.Errorf("puerto UDP reservado para WireGuard")
	}
	if _, ok := s.svc.Store.PeerByIP(targetIP); !ok {
		return "", fmt.Errorf("la IP destino %s no pertenece a ningún peer", targetIP)
	}
	return name, nil
}

func (s *Server) listForwards(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Store.Forwards())
}

// This checks the tunnel destination, never claims to verify Internet access.
func (s *Server) checkForward(w http.ResponseWriter, r *http.Request) {
	fwd, ok := s.findForwardByID(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "forward no encontrado")
		return
	}
	result := map[string]any{"forward": fwd, "external_access_verified": false, "target_checked": false}
	if fwd.Protocol == "udp" {
		result["detail"] = "UDP requires an application-specific request and response; no generic probe performed"
	} else if fwd.Enabled {
		dialer := net.Dialer{Timeout: 3 * time.Second}
		conn, err := dialer.DialContext(r.Context(), "tcp", net.JoinHostPort(fwd.TargetIP, fmt.Sprint(fwd.TargetPort)))
		result["target_checked"] = true
		result["target_tcp_connected"] = err == nil
		if err != nil {
			result["detail"] = err.Error()
		} else {
			conn.Close()
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) reconcileForwards(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	if err := s.svc.ReloadForwards(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) createForward(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	var req forwardRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}
	name, err := s.validateForward(req.Name, req.PublicPort, strings.TrimSpace(req.TargetIP), req.TargetPort, req.Protocol)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	proto, _ := normalizeProtocol(req.Protocol)
	if req.ManagedBy != "" && req.ManagedBy != "vps" && !strings.HasPrefix(req.ManagedBy, "umbrel:") {
		writeError(w, http.StatusBadRequest, "managed_by inválido")
		return
	}
	if len(req.ManagedBy) > 80 {
		writeError(w, http.StatusBadRequest, "managed_by demasiado largo")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	fwd := state.Forward{
		ID:         state.NewID(),
		AccessMode: req.AccessMode,
		Domain:     req.Domain,
		Name:       name,
		PublicPort: req.PublicPort,
		TargetIP:   strings.TrimSpace(req.TargetIP),
		TargetPort: req.TargetPort,
		Protocol:   proto,
		ManagedBy:  req.ManagedBy,
		Enabled:    enabled,
	}
	if (fwd.AccessMode == "https" || fwd.AccessMode == "tls") && !req.AcceptACMETerms {
		writeError(w, http.StatusBadRequest, "debes aceptar las condiciones de Let's Encrypt (accept_acme_terms)")
		return
	}
	_, apiPort, _ := s.svc.Cfg.ParseAPIHostPort()
	if err := edge.Validate(append(s.svc.Store.Forwards(), fwd), apiPort); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.Store.AddForward(fwd); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "ya está en uso") {
			code = http.StatusConflict
		}
		writeError(w, code, err.Error())
		return
	}
	created, _ := s.findForwardByID(fwd.ID)

	if err := s.svc.ReloadForwards(r.Context()); err != nil {
		_, _, _ = s.svc.Store.RemoveForward(created.ID)
		_ = s.svc.ReloadForwards(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar nftables: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) findForwardByPort(port int, proto string) (state.Forward, bool) {
	for _, f := range s.svc.Store.Forwards() {
		if f.PublicPort == port && f.Protocol == proto {
			return f, true
		}
	}
	return state.Forward{}, false
}

func (s *Server) findForwardByID(id string) (state.Forward, bool) {
	for _, f := range s.svc.Store.Forwards() {
		if f.ID == id {
			return f, true
		}
	}
	return state.Forward{}, false
}

type forwardPatch struct {
	AcceptACMETerms bool    `json:"accept_acme_terms"`
	AccessMode      *string `json:"access_mode"`
	Domain          *string `json:"domain"`
	Name            *string `json:"name"`
	PublicPort      *int    `json:"public_port"`
	TargetIP        *string `json:"target_ip"`
	TargetPort      *int    `json:"target_port"`
	Protocol        *string `json:"protocol"`
	ManagedBy       *string `json:"managed_by"`
	Enabled         *bool   `json:"enabled"`
}

func (s *Server) patchForward(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	id := r.PathValue("id")
	before, ok := s.findForwardByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "forward no encontrado")
		return
	}
	var patch forwardPatch
	if err := decode(w, r, &patch); err != nil {
		writeError(w, http.StatusBadRequest, "JSON inválido: "+err.Error())
		return
	}

	updated := before
	if patch.AccessMode != nil {
		updated.AccessMode = *patch.AccessMode
	}
	if patch.Domain != nil {
		updated.Domain = *patch.Domain
	}
	if patch.ManagedBy != nil {
		owner := *patch.ManagedBy
		if len(owner) > 80 || (owner != "" && owner != "vps" && !strings.HasPrefix(owner, "umbrel:")) {
			writeError(w, http.StatusBadRequest, "managed_by inválido")
			return
		}
		if before.ManagedBy != "" && before.ManagedBy != owner {
			writeError(w, http.StatusConflict, "no se puede cambiar el propietario de una publicación")
			return
		}
		updated.ManagedBy = owner
	}
	if patch.Name != nil {
		updated.Name = strings.TrimSpace(*patch.Name)
	}
	if patch.PublicPort != nil {
		updated.PublicPort = *patch.PublicPort
	}
	if patch.TargetIP != nil {
		updated.TargetIP = strings.TrimSpace(*patch.TargetIP)
	}
	if patch.TargetPort != nil {
		updated.TargetPort = *patch.TargetPort
	}
	if patch.Protocol != nil {
		updated.Protocol = *patch.Protocol
	}
	if patch.Enabled != nil {
		updated.Enabled = *patch.Enabled
	}

	name, err := s.validateForward(updated.Name, updated.PublicPort, updated.TargetIP, updated.TargetPort, updated.Protocol)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	updated.Name = name
	proto, _ := normalizeProtocol(updated.Protocol)
	updated.Protocol = proto
	if (updated.AccessMode == "https" || updated.AccessMode == "tls") && (before.AccessMode != updated.AccessMode || before.Domain != updated.Domain) && !patch.AcceptACMETerms {
		writeError(w, http.StatusBadRequest, "debes aceptar las condiciones de Let's Encrypt")
		return
	}
	candidates := s.svc.Store.Forwards()
	for i := range candidates {
		if candidates[i].ID == id {
			candidates[i] = updated
		}
	}
	_, apiPort, _ := s.svc.Cfg.ParseAPIHostPort()
	if err := edge.Validate(candidates, apiPort); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if _, err := s.svc.Store.UpdateForward(id, func(f *state.Forward) error {
		*f = updated
		return nil
	}); err != nil {
		code := http.StatusBadRequest
		if strings.Contains(err.Error(), "ya está en uso") {
			code = http.StatusConflict
		}
		writeError(w, code, err.Error())
		return
	}

	if err := s.svc.ReloadForwards(r.Context()); err != nil {
		_, _ = s.svc.Store.UpdateForward(id, func(f *state.Forward) error { *f = before; return nil })
		_ = s.svc.ReloadForwards(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar nftables: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) deleteForward(w http.ResponseWriter, r *http.Request) {
	s.forwardMu.Lock()
	defer s.forwardMu.Unlock()
	id := r.PathValue("id")
	before, ok := s.findForwardByID(id)
	if !ok {
		writeError(w, http.StatusNotFound, "forward no encontrado")
		return
	}
	if _, _, err := s.svc.Store.RemoveForward(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.svc.ReloadForwards(r.Context()); err != nil {
		_ = s.svc.Store.AddForward(before)
		_ = s.svc.ReloadForwards(r.Context())
		writeError(w, http.StatusInternalServerError, "no se pudo aplicar nftables: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) rotateToken(w http.ResponseWriter, _ *http.Request) {
	token, err := config.GenerateToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := s.svc.Paths.SaveToken(token); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token})
}

// Pairing is exposed for tests and future use.
func (s *Server) Pairing() (pair.Pairing, error) {
	return s.svc.Pairing()
}
