package firewall

import (
	"strings"
	"testing"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/state"
)

func TestRulesIncludeForwardAndGuard(t *testing.T) {
	cfg := config.Default()
	m := New(config.DefaultPaths(), cfg, &execx.Fake{})
	rules := m.Rules([]state.Forward{
		{Name: "web", PublicPort: 8080, TargetIP: "10.0.0.2", TargetPort: 3006, Protocol: "tcp", Enabled: true},
		{Name: "off", PublicPort: 9000, TargetIP: "10.0.0.2", TargetPort: 9000, Protocol: "tcp", Enabled: false},
	})

	checks := []string{
		"table inet umbrel_tunnel",
		`iifname "wg0" tcp dport 8080 accept`,
		`iifname "lo" tcp dport 8080 accept`,
		"tcp dport 8080 drop",
		`iifname != "wg0" tcp dport 8080 dnat to 10.0.0.2:3006`,
		`iifname "wg0" accept`,
		`oifname "wg0" accept`,
		`oifname "wg0" masquerade`,
	}
	for _, want := range checks {
		if !strings.Contains(rules, want) {
			t.Fatalf("falta %q en:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "9000") {
		t.Fatalf("forward desactivado incluido:\n%s", rules)
	}
}

func TestRulesPublicAPIOmitsGuard(t *testing.T) {
	cfg := config.Default()
	cfg.PublicAPI = true
	m := New(config.DefaultPaths(), cfg, &execx.Fake{})
	rules := m.Rules(nil)
	if strings.Contains(rules, "tcp dport 8080 drop") {
		t.Fatalf("guard presente con API pública:\n%s", rules)
	}
}
