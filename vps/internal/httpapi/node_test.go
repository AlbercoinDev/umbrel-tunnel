package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"umbrel-tunnel/internal/state"
)

const nodeToken = "oficina-token-0123456789abcdef"

// asNode calls the API from a tunnel address, as WireGuard would deliver it.
func (h *harness) asNode(method, path, token, remote string, body any) (int, []byte) {
	h.t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = remote + ":40000"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func (h *harness) addNode(domain, token string, keyByte byte) state.Peer {
	h.t.Helper()
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{keyByte}, 32))
	resp, body := h.do(http.MethodPost, "/api/peers", h.token, map[string]string{
		"name": "oficina", "public_key": pub, "domain": domain, "token": token,
	})
	var peer state.Peer
	h.decode(resp, body, &peer)
	return peer
}

func forwardBody(target string, port int, mode, domain string) map[string]any {
	return map[string]any{
		"name": "svc", "public_port": port, "target_ip": target, "target_port": 3000,
		"protocol": "tcp", "access_mode": mode, "domain": domain, "accept_acme_terms": true,
	}
}

func TestNodeGetsNextFreeAddressAndHidesTokenHash(t *testing.T) {
	h := newHarness(t)
	node := h.addNode("oficina.example", nodeToken, 9)
	if node.AllowedIP != "10.0.0.3" || node.Domain != "oficina.example" {
		t.Fatalf("nodo inesperado: %+v", node)
	}
	_, body := h.do(http.MethodGet, "/api/peers", h.token, nil)
	if strings.Contains(string(body), "token_sha256") || strings.Contains(string(body), TokenHash(nodeToken)) {
		t.Fatalf("hash del token expuesto: %s", body)
	}
}

func TestNodeTokenOnlyWorksFromItsTunnelAddress(t *testing.T) {
	h := newHarness(t)
	h.addNode("oficina.example", nodeToken, 9)
	if code, _ := h.asNode(http.MethodGet, "/api/forwards", nodeToken, "10.0.0.3", nil); code != http.StatusOK {
		t.Fatalf("nodo rechazado desde su IP: %d", code)
	}
	for _, remote := range []string{"10.0.0.2", "127.0.0.1", "203.0.113.5"} {
		if code, _ := h.asNode(http.MethodGet, "/api/forwards", nodeToken, remote, nil); code != http.StatusUnauthorized {
			t.Fatalf("token de nodo aceptado desde %s: %d", remote, code)
		}
	}
}

func TestNodeOnlySeesAndChangesItsOwnPublications(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodPost, "/api/forwards", h.token, forwardBody("10.0.0.2", 443, "https", "mempool.casa.example"))
	var foreign state.Forward
	h.decode(resp, body, &foreign)
	h.addNode("oficina.example", nodeToken, 9)
	node := func(method, path string, body any) (int, []byte) {
		return h.asNode(method, path, nodeToken, "10.0.0.3", body)
	}

	if code, body := node(http.MethodGet, "/api/forwards", nil); code != http.StatusOK || strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("el nodo ve reglas ajenas: %d %s", code, body)
	}
	// Same app, same public port, different domain: routed by name.
	code, body := node(http.MethodPost, "/api/forwards", forwardBody("10.0.0.3", 443, "https", "mempool.oficina.example"))
	if code != http.StatusCreated {
		t.Fatalf("publicación propia rechazada: %d %s", code, body)
	}
	var own state.Forward
	_ = json.Unmarshal(body, &own)
	if own.ManagedBy != "umbrel:10.0.0.3" {
		t.Fatalf("managed_by no forzado: %q", own.ManagedBy)
	}
	for name, req := range map[string]map[string]any{
		"destino ajeno":   forwardBody("10.0.0.2", 9100, "direct", ""),
		"dominio ajeno":   forwardBody("10.0.0.3", 443, "https", "otro.casa.example"),
		"dominio parcial": forwardBody("10.0.0.3", 443, "https", "xoficina.example"),
	} {
		if code, body := node(http.MethodPost, "/api/forwards", req); code != http.StatusForbidden {
			t.Fatalf("%s aceptado: %d %s", name, code, body)
		}
	}
	for _, method := range []string{http.MethodPatch, http.MethodDelete} {
		if code, _ := node(method, "/api/forwards/"+foreign.ID, map[string]any{"enabled": false}); code != http.StatusNotFound {
			t.Fatalf("%s sobre regla ajena: %d", method, code)
		}
	}
	if code, _ := node(http.MethodGet, "/api/forwards/"+foreign.ID+"/check", nil); code != http.StatusNotFound {
		t.Fatalf("check sobre regla ajena: %d", code)
	}
	if code, _ := node(http.MethodPatch, "/api/forwards/"+own.ID, map[string]any{"target_ip": "10.0.0.2"}); code != http.StatusForbidden {
		t.Fatalf("el nodo redirigió su regla a otro Umbrel: %d", code)
	}
	// A direct port has no name: whoever holds it keeps it.
	h.do(http.MethodPost, "/api/forwards", h.token, forwardBody("10.0.0.2", 9735, "direct", ""))
	if code, _ := node(http.MethodPost, "/api/forwards", forwardBody("10.0.0.3", 9735, "direct", "")); code != http.StatusConflict {
		t.Fatalf("puerto directo compartido: %d", code)
	}
	_, all := h.do(http.MethodGet, "/api/forwards", h.token, nil)
	var forwards []state.Forward
	_ = json.Unmarshal(all, &forwards)
	if len(forwards) != 3 {
		t.Fatalf("el administrador debe ver todas las reglas: %d", len(forwards))
	}
}

func TestNodeCannotManageOtherPeersOrCreatePeers(t *testing.T) {
	h := newHarness(t)
	node := h.addNode("oficina.example", nodeToken, 9)
	call := func(method, path string, body any) int {
		code, _ := h.asNode(method, path, nodeToken, "10.0.0.3", body)
		return code
	}
	_, body := h.asNode(http.MethodGet, "/api/peers", nodeToken, "10.0.0.3", nil)
	var peers []state.Peer
	_ = json.Unmarshal(body, &peers)
	if len(peers) != 1 || peers[0].ID != node.ID {
		t.Fatalf("el nodo ve otros peers: %s", body)
	}
	if code := call(http.MethodDelete, "/api/peers/"+h.umbrel.ID, nil); code != http.StatusNotFound {
		t.Fatalf("borró un peer ajeno: %d", code)
	}
	if code := call(http.MethodPost, "/api/peers", map[string]string{"name": "x", "allowed_ip": "10.0.0.9"}); code != http.StatusForbidden {
		t.Fatalf("un nodo creó peers: %d", code)
	}
	if code := call(http.MethodPut, "/api/peers/"+node.ID+"/node", map[string]string{"domain": "example", "token": nodeToken}); code != http.StatusForbidden {
		t.Fatalf("un nodo cambió su dominio: %d", code)
	}
	_, status := h.asNode(http.MethodGet, "/api/status", nodeToken, "10.0.0.3", nil)
	var st statusResponse
	_ = json.Unmarshal(status, &st)
	if st.PeersTotal != 1 || st.Peers[0].ID != node.ID {
		t.Fatalf("status filtra mal: %+v", st)
	}
}

func TestOverlappingNodeDomainsAreRejected(t *testing.T) {
	h := newHarness(t)
	h.addNode("oficina.example", nodeToken, 9)
	for i, domain := range []string{"oficina.example", "app.oficina.example", "example"} {
		pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(20 + i)}, 32))
		resp, body := h.do(http.MethodPost, "/api/peers", h.token, map[string]string{
			"name": "otro", "public_key": pub, "domain": domain, "token": nodeToken + "x",
		})
		if resp.StatusCode != http.StatusConflict && resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("dominio solapado %s aceptado: %d %s", domain, resp.StatusCode, body)
		}
	}
}

func TestClaimConvertsExistingUmbrelAndRotateKeepsAdmin(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(http.MethodPost, "/api/forwards", h.token, forwardBody("10.0.0.2", 443, "https", "mempool.casa.example"))
	h.decode(resp, body, &state.Forward{})
	const casa = "casa-token-0123456789abcdefgh"
	resp, body = h.do(http.MethodPut, "/api/peers/"+h.umbrel.ID+"/node", h.token, map[string]string{"domain": "casa.example", "token": casa})
	h.decode(resp, body, &state.Peer{})
	code, list := h.asNode(http.MethodGet, "/api/forwards", casa, "10.0.0.2", nil)
	if code != http.StatusOK || !strings.Contains(string(list), "mempool.casa.example") {
		t.Fatalf("el Umbrel convertido no ve sus reglas: %d %s", code, list)
	}
	code, rotated := h.asNode(http.MethodPost, "/api/token/rotate", casa, "10.0.0.2", nil)
	var got map[string]string
	_ = json.Unmarshal(rotated, &got)
	if code != http.StatusOK || got["token"] == "" {
		t.Fatalf("rotación de token de nodo: %d %s", code, rotated)
	}
	if code, _ := h.asNode(http.MethodGet, "/api/forwards", casa, "10.0.0.2", nil); code != http.StatusUnauthorized {
		t.Fatalf("token de nodo antiguo sigue válido: %d", code)
	}
	if code, _ := h.asNode(http.MethodGet, "/api/forwards", got["token"], "10.0.0.2", nil); code != http.StatusOK {
		t.Fatalf("token de nodo nuevo rechazado: %d", code)
	}
	if resp, _ := h.do(http.MethodGet, "/api/forwards", h.token, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("un nodo rotó el token de administración: %d", resp.StatusCode)
	}
	// A claim must not strand publications outside the new domain.
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	resp, body = h.do(http.MethodPost, "/api/peers", h.token, map[string]string{"name": "b", "public_key": pub, "allowed_ip": "10.0.0.4"})
	var b state.Peer
	h.decode(resp, body, &b)
	h.do(http.MethodPost, "/api/forwards", h.token, forwardBody("10.0.0.4", 8443, "tls", "electrs.otro.example"))
	if resp, _ := h.do(http.MethodPut, "/api/peers/"+b.ID+"/node", h.token, map[string]string{"domain": "oficina.example", "token": nodeToken}); resp.StatusCode != http.StatusConflict {
		t.Fatalf("claim con publicaciones fuera del dominio: %d", resp.StatusCode)
	}
}
