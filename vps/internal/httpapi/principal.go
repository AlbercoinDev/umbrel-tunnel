package httpapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net"
	"net/http"
	"strings"

	"umbrel-tunnel/internal/state"
)

// principal is who is calling the API. The administrator token (the VPS owner,
// CLI and dashboard, or a single-Umbrel install) can do everything. A node of a
// shared VPS only sees and changes what targets its own tunnel address.
type principal struct {
	admin bool
	peer  state.Peer
}

type principalKey struct{}

// TokenHash is the value stored in Peer.TokenSHA256.
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func principalFrom(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}

// owns reports whether a publication belongs to the caller. Ownership is the
// tunnel destination: WireGuard binds each tunnel address to one key, so a
// node cannot forge it.
func (p principal) owns(f state.Forward) bool {
	return p.admin || f.TargetIP == p.peer.AllowedIP
}

func (p principal) ownsPeer(id string) bool {
	return p.admin || p.peer.ID == id
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		admin, err := s.svc.Paths.LoadToken()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "token no disponible")
			return
		}
		header := r.Header.Get("Authorization")
		const prefix = "Bearer "
		token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
		var who principal
		ok := false
		if strings.HasPrefix(header, prefix) && token != "" {
			if subtle.ConstantTimeCompare([]byte(token), []byte(admin)) == 1 {
				who, ok = principal{admin: true}, true
			} else if peer, found := s.svc.Store.PeerByTokenHash(TokenHash(token)); found && remoteIP(r) == peer.AllowedIP {
				// A node token only works from its own tunnel address, so a
				// leaked token is useless outside that Umbrel's WireGuard key.
				who, ok = principal{peer: peer}, true
			}
		}
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer realm="umbrel-tunnel"`)
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, who)))
	}
}

// adminOnly hides administrator endpoints from nodes.
func (s *Server) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r).admin {
			writeError(w, http.StatusForbidden, "solo el administrador del VPS")
			return
		}
		next(w, r)
	})
}

// peerScoped answers 404 for peers that are not the caller's, without
// revealing whether they exist.
func (s *Server) peerScoped(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !principalFrom(r).ownsPeer(r.PathValue("id")) {
			writeError(w, http.StatusNotFound, "peer no encontrado")
			return
		}
		next(w, r)
	})
}

// forwardScoped answers 404 for publications that are not the caller's.
func (s *Server) forwardScoped(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request) {
		if f, ok := s.findForwardByID(r.PathValue("id")); ok && !principalFrom(r).owns(f) {
			writeError(w, http.StatusNotFound, "forward no encontrado")
			return
		}
		next(w, r)
	})
}

// scopeForward applies node limits to a publication before it is stored.
func scopeForward(p principal, f *state.Forward) (int, string) {
	if p.admin {
		return 0, ""
	}
	if f.TargetIP != p.peer.AllowedIP {
		return http.StatusForbidden, "solo puedes publicar hacia tu propio Umbrel (" + p.peer.AllowedIP + ")"
	}
	if f.Domain != "" && !state.InDomain(f.Domain, p.peer.Domain) {
		return http.StatusForbidden, "el dominio " + f.Domain + " no pertenece a este Umbrel; usa " + p.peer.Domain + " o un subdominio"
	}
	f.ManagedBy = "umbrel:" + p.peer.AllowedIP
	return 0, ""
}
