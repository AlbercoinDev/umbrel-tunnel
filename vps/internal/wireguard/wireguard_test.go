package wireguard

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/state"
)

func TestStatusParsesDump(t *testing.T) {
	now := time.Now().Unix()
	dump := strings.Join([]string{
		"priv\tpub\t51820\toff",
		"peerpub\t(none)\t203.0.113.10:12345\t10.0.0.2/32\t" + strconv.FormatInt(now-10, 10) + "\t100\t200\t25",
		"oldpeer\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff",
	}, "\n")

	run := &execx.Fake{Outputs: map[string][]byte{"wg show wg0 dump": []byte(dump)}}
	m := New(config.DefaultPaths(), config.Default(), run)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Running || st.ListenPort != 51820 || len(st.Peers) != 2 {
		t.Fatalf("status inesperado: %+v", st)
	}
	if !st.Peers[0].Connected || st.Peers[0].Rx != 100 || st.Peers[0].Tx != 200 {
		t.Fatalf("peer conectado mal parseado: %+v", st.Peers[0])
	}
	if st.Peers[1].Connected {
		t.Fatal("peer sin handshake marcado como conectado")
	}
}

func TestClientConfig(t *testing.T) {
	cfg := config.Default()
	cfg.Endpoint = "203.0.113.10"
	m := New(config.DefaultPaths(), cfg, &execx.Fake{})
	out := m.ClientConfig("priv", "pub", "10.0.0.2")
	for _, want := range []string{"PrivateKey = priv", "Address = 10.0.0.2/24", "Endpoint = 203.0.113.10:51820", "AllowedIPs = 10.0.0.0/24", "PersistentKeepalive = 25"} {
		if !strings.Contains(out, want) {
			t.Fatalf("falta %q en:\n%s", want, out)
		}
	}
}

func TestServerConfigIncludesPeers(t *testing.T) {
	m := New(config.DefaultPaths(), config.Default(), &execx.Fake{})
	out := m.ServerConfig("priv", []state.Peer{
		{Name: "umbrel", PublicKey: "pub", AllowedIP: "10.0.0.2"},
	})
	for _, want := range []string{"# Managed by umbrel-tunnel", "Address = 10.0.0.1/24", "PublicKey = pub", "AllowedIPs = 10.0.0.2/32"} {
		if !strings.Contains(out, want) {
			t.Fatalf("falta %q en:\n%s", want, out)
		}
	}
}
