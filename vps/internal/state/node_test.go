package state

import "testing"

func TestDomainHelpersMatchWholeLabels(t *testing.T) {
	cases := []struct {
		a, b    string
		overlap bool
	}{
		{"casa.example", "casa.example", true},
		{"app.casa.example", "casa.example", true},
		{"casa.example", "oficina.example", false},
		{"xcasa.example", "casa.example", false},
		{"", "casa.example", false},
	}
	for _, c := range cases {
		if DomainsOverlap(c.a, c.b) != c.overlap || DomainsOverlap(c.b, c.a) != c.overlap {
			t.Fatalf("DomainsOverlap(%q, %q) != %v", c.a, c.b, c.overlap)
		}
	}
	if !InDomain("mempool.casa.example", "casa.example") || InDomain("mempool.xcasa.example", "casa.example") || InDomain("casa.example", "") {
		t.Fatal("InDomain no respeta etiquetas completas")
	}
}

func TestNodeFieldsPersistAndTLSPortIsSharedByName(t *testing.T) {
	paths := testPaths(t)
	s, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddPeer(Peer{Name: "a", PublicKey: "ka", AllowedIP: "10.0.0.2", Domain: "casa.example", TokenSHA256: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddPeer(Peer{Name: "b", PublicKey: "kb", AllowedIP: "10.0.0.3", Domain: "app.casa.example"}); err == nil {
		t.Fatal("dominio solapado aceptado")
	}
	reopened, err := Open(paths)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := reopened.PeerByTokenHash("h"); !ok || p.Domain != "casa.example" || !p.IsNode() || p.Public().TokenSHA256 != "" {
		t.Fatalf("nodo no persistido: %+v", p)
	}
	tlsRule := func(domain, ip string) Forward {
		return Forward{PublicPort: 50002, Protocol: "tcp", AccessMode: "tls", Domain: domain, TargetIP: ip, Enabled: true}
	}
	if err := s.AddForward(tlsRule("electrs.casa.example", "10.0.0.2")); err != nil {
		t.Fatal(err)
	}
	if err := s.AddForward(tlsRule("electrs.oficina.example", "10.0.0.3")); err != nil {
		t.Fatalf("TLS con otro dominio en el mismo puerto: %v", err)
	}
	if err := s.AddForward(Forward{PublicPort: 50002, Protocol: "tcp", TargetIP: "10.0.0.3"}); err == nil {
		t.Fatal("puerto directo encima de TLS aceptado")
	}
}
