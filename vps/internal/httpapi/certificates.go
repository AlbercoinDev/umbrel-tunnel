package httpapi

import "net/http"

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
	writeJSON(w, http.StatusOK, s.svc.Edge.Status())
}
