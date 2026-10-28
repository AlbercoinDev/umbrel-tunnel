package httpapi

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"os"
	"strings"
	"testing"
)

func prepareTestRotation(t *testing.T, h *harness) *peerRotation {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	resp, body := h.do("POST", "/api/peers/"+h.umbrel.ID+"/rotation", h.token, map[string]string{"public_key": key})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("prepare: %d %s", resp.StatusCode, body)
	}
	return h.api.rotation
}

func TestRotationCommitsOnlyAfterNewTunnelConfirms(t *testing.T) {
	h := newHarness(t)
	r := prepareTestRotation(t, h)
	before, _ := os.ReadFile(h.paths.WGConfFile())
	if strings.Contains(string(before), r.publicKey) {
		t.Fatal("new key applied before prepare response")
	}
	confirm := func() int {
		resp, _ := h.do("POST", "/api/peers/"+h.umbrel.ID+"/rotation/confirm", h.token, map[string]string{"rotation_id": r.id})
		return resp.StatusCode
	}
	if confirm() != http.StatusConflict {
		t.Fatal("confirmed before switching")
	}
	h.api.switchRotation(r)
	peer, _ := h.api.svc.Store.PeerByID(h.umbrel.ID)
	if peer.PublicKey != h.umbrel.PublicKey {
		t.Fatal("unconfirmed key persisted")
	}
	data, err := os.ReadFile(h.paths.WGConfFile())
	if err != nil || !strings.Contains(string(data), r.publicKey) {
		t.Fatal("new live config missing", err)
	}
	if confirm() != http.StatusOK || confirm() != http.StatusOK {
		t.Fatal("confirmation must be idempotent")
	}
	h.api.expireRotation(r)
	peer, _ = h.api.svc.Store.PeerByID(h.umbrel.ID)
	if peer.PublicKey != r.publicKey {
		t.Fatal("confirmed key rolled back")
	}
}

func TestUnconfirmedRotationRollsBackAndBlocksPeerMutations(t *testing.T) {
	h := newHarness(t)
	r := prepareTestRotation(t, h)
	resp, _ := h.do("DELETE", "/api/peers/"+h.umbrel.ID, h.token, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatal("peer mutation accepted during rotation")
	}
	h.api.switchRotation(r)
	if !h.api.expireRotation(r) {
		t.Fatal("rollback failed")
	}
	data, err := os.ReadFile(h.paths.WGConfFile())
	if err != nil || !strings.Contains(string(data), h.umbrel.PublicKey) || strings.Contains(string(data), r.publicKey) {
		t.Fatal("old key not restored", err)
	}
	resp, _ = h.do("POST", "/api/peers/"+h.umbrel.ID+"/rotation/confirm", h.token, map[string]string{"rotation_id": r.id})
	if resp.StatusCode != http.StatusConflict {
		t.Fatal("expired rotation confirmed")
	}
}

func TestRotationRequiresAuthAndRejectsDuplicateKey(t *testing.T) {
	h := newHarness(t)
	path := "/api/peers/" + h.umbrel.ID + "/rotation"
	resp, _ := h.do("POST", path, "", map[string]string{"public_key": h.umbrel.PublicKey})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("rotation allowed without auth")
	}
	resp, _ = h.do("POST", path, h.token, map[string]string{"public_key": h.umbrel.PublicKey})
	if resp.StatusCode != http.StatusConflict {
		t.Fatal("duplicate key accepted")
	}
}

func TestPeerConfigRejectsUnrelatedLegacyPrivateKey(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.paths.ClientKeyFile(), []byte("unrelated-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp, body := h.do("GET", "/api/peers/"+h.umbrel.ID+"/config", h.token, nil)
	if resp.StatusCode != http.StatusConflict || !bytes.Contains(body, []byte(`"code":"http_409"`)) {
		t.Fatalf("unrelated legacy key accepted: %d %s", resp.StatusCode, body)
	}
}
