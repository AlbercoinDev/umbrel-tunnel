package firewall

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/state"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	root := t.TempDir()
	return config.Paths{
		Etc:       filepath.Join(root, "etc"),
		State:     filepath.Join(root, "state"),
		WireGuard: filepath.Join(root, "wg"),
		Run:       filepath.Join(root, "run"),
	}
}

func testForwards() []state.Forward {
	return []state.Forward{
		{Name: "web", PublicPort: 8080, TargetIP: "10.0.0.2", TargetPort: 3006, Protocol: "tcp", Enabled: true},
		{Name: "off", PublicPort: 9000, TargetIP: "10.0.0.2", TargetPort: 9000, Protocol: "tcp", Enabled: false},
	}
}

func TestRulesIncludeForwardAndGuard(t *testing.T) {
	cfg := config.Default()
	m := New(config.DefaultPaths(), cfg, &execx.Fake{})
	rules := m.Rules(testForwards())

	checks := []string{
		"table inet umbrel_tunnel",
		`iifname "wg0" tcp dport 8080 accept`,
		`iifname "lo" tcp dport 8080 accept`,
		"tcp dport 8080 drop",
		`iifname != "wg0" tcp dport 8080 dnat ip to 10.0.0.2:3006`,
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

func TestSecurePublicationsNeverGenerateCleartextDNAT(t *testing.T) {
	m := New(config.DefaultPaths(), config.Default(), &execx.Fake{})
	forwards := testForwards()
	forwards = append(forwards, state.Forward{AccessMode: "https", Domain: "web.example.org", PublicPort: 443, TargetIP: "10.0.0.2", TargetPort: 20000, Protocol: "tcp", Enabled: true}, state.Forward{AccessMode: "tls", Domain: "electrs.example.org", PublicPort: 50002, TargetIP: "10.0.0.2", TargetPort: 20001, Protocol: "tcp", Enabled: true})
	rules := m.Rules(forwards)
	if strings.Contains(rules, "dport 443") || strings.Contains(rules, "dport 50002") {
		t.Fatalf("secure ports leaked to DNAT: %s", rules)
	}
	if !strings.Contains(rules, "dport 8080 dnat") {
		t.Fatal("existing direct forward removed")
	}
}

// A `dnat` without an explicit family is rejected by nft in an `inet` table.
func TestRulesAlwaysSpecifyDnatFamily(t *testing.T) {
	m := New(config.DefaultPaths(), config.Default(), &execx.Fake{})
	rules := m.Rules(testForwards())

	for _, line := range strings.Split(rules, "\n") {
		if !strings.Contains(line, "dnat") {
			continue
		}
		if !strings.Contains(line, "dnat ip to ") {
			t.Fatalf("dnat sin familia explícita: %q", line)
		}
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

// Apply must validate the rendered ruleset before persisting it, otherwise a
// rejected ruleset stays on disk and breaks umbrel-tunnel-firewall at boot.
func TestApplyDoesNotWriteInvalidRules(t *testing.T) {
	paths := testPaths(t)
	run := &execx.Fake{Errors: map[string]error{
		"nft -c -f -": errors.New("sintaxis inválida"),
	}}
	m := New(paths, config.Default(), run)

	err := m.Apply(context.Background(), testForwards())
	if err == nil {
		t.Fatal("Apply aceptó un ruleset inválido")
	}
	if _, statErr := os.Stat(paths.RulesFile()); !os.IsNotExist(statErr) {
		t.Fatalf("rules.nft no debería existir tras un fallo de validación: %v", statErr)
	}
	for _, call := range run.Calls {
		if len(call.Args) > 0 && call.Args[0] == "-f" && call.Args[1] == paths.RulesFile() {
			t.Fatal("se aplicó nftables pese al fallo de validación")
		}
	}
}

func TestApplyValidatesThenPersistsAndLoads(t *testing.T) {
	paths := testPaths(t)
	run := &execx.Fake{}
	m := New(paths, config.Default(), run)

	if err := m.Apply(context.Background(), testForwards()); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	data, err := os.ReadFile(paths.RulesFile())
	if err != nil {
		t.Fatalf("leer rules.nft: %v", err)
	}
	if !strings.Contains(string(data), "dnat ip to 10.0.0.2:3006") {
		t.Fatalf("rules.nft sin el DNAT esperado:\n%s", data)
	}

	want := []execx.Call{
		{Name: "nft", Args: []string{"-c", "-f", "-"}},
		{Name: "nft", Args: []string{"delete", "table", "inet", "umbrel_tunnel"}},
		{Name: "nft", Args: []string{"-f", paths.RulesFile()}},
	}
	if len(run.Calls) != len(want) {
		t.Fatalf("llamadas inesperadas: %+v", run.Calls)
	}
	for i := range want {
		if run.Calls[i].Name != want[i].Name || strings.Join(run.Calls[i].Args, " ") != strings.Join(want[i].Args, " ") {
			t.Fatalf("llamada %d = %s %v, quiero %s %v", i, run.Calls[i].Name, run.Calls[i].Args, want[i].Name, want[i].Args)
		}
	}
	if len(run.Calls[0].Input) == 0 {
		t.Fatal("la validación no recibió el ruleset por stdin")
	}
}

// Regression test for the `dnat ip` bug: the real nft parser must accept the
// generated ruleset. It needs nft and an unprivileged network namespace, so it
// is skipped when either is unavailable (for example on some CI runners).
func TestRulesAcceptedByNft(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft no está instalado")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("unshare no está instalado")
	}
	if out, err := exec.Command("unshare", "-rn", "true").CombinedOutput(); err != nil {
		t.Skipf("sin namespaces de red no privilegiados: %v: %s", err, strings.TrimSpace(string(out)))
	}

	m := New(config.DefaultPaths(), config.Default(), &execx.Fake{})
	cmd := exec.Command("unshare", "-rn", nft, "-c", "-f", "-")
	cmd.Stdin = strings.NewReader(m.Rules(testForwards()))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft rechazó el ruleset: %v\n%s", err, out)
	}
}
