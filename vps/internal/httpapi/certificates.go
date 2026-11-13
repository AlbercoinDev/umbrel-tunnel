package httpapi

import (
	"net/http"

	"umbrel-tunnel/internal/state"
)

func (s *Server) retryCertificates(w http.ResponseWriter, r *http.Request) {
	if s.svc.Edge == nil {
		writeError(w, http.StatusServiceUnavailable, "TLS no disponible")
		return
	}
	s.svc.Edge.Retry()
	writeJSON(w, http.StatusAccepted, map[string]bool{"scheduled": true})
}

func (s *Server) certificates(w http.ResponseWriter, r *http.Request) {
	if s.svc.Edge == nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	who := principalFrom(r)
	out := []map[string]any{}
	for _, item := range s.svc.Edge.Status() {
		domain, _ := item["domain"].(string)
		if who.admin || state.InDomain(domain, who.peer.Domain) {
			out = append(out, item)
		}
	}
	writeJSON(w, http.StatusOK, out)
}
