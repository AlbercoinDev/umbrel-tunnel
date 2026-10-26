// Package firewall renders and applies the nftables ruleset.
package firewall

import (
	"context"
	"fmt"
	"strings"

	"umbrel-tunnel/internal/config"
	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/fsutil"
	"umbrel-tunnel/internal/state"
)

// Manager owns the `inet umbrel_tunnel` nftables table.
type Manager struct {
	paths config.Paths
	cfg   config.Config
	run   execx.Runner
}

// New creates a Manager.
func New(paths config.Paths, cfg config.Config, run execx.Runner) *Manager {
	return &Manager{paths: paths, cfg: cfg, run: run}
}

// Rules renders the complete ruleset. It is deterministic so it can be
// persisted to /etc/umbrel-tunnel/rules.nft and restored at boot.
func (m *Manager) Rules(forwards []state.Forward) string {
	var b strings.Builder
	b.WriteString("# Managed by umbrel-tunnel - no editar a mano\n")
	b.WriteString("table inet umbrel_tunnel {\n")

	b.WriteString("    chain input {\n")
	b.WriteString("        type filter hook input priority filter; policy accept;\n")
	if !m.cfg.PublicAPI {
		_, port, err := m.cfg.ParseAPIHostPort()
		if err == nil {
			fmt.Fprintf(&b, "        iifname %q tcp dport %d accept\n", m.cfg.Interface, port)
			// Local checks (installer, doctor) connect to 10.0.0.1 through
			// loopback because it is a local address, not through wg0.
			fmt.Fprintf(&b, "        iifname \"lo\" tcp dport %d accept\n", port)
			fmt.Fprintf(&b, "        tcp dport %d drop\n", port)
		}
	}
	b.WriteString("    }\n\n")

	b.WriteString("    chain forward {\n")
	b.WriteString("        type filter hook forward priority filter; policy accept;\n")
	b.WriteString("        ct state established,related accept\n")
	fmt.Fprintf(&b, "        iifname %q accept\n", m.cfg.Interface)
	fmt.Fprintf(&b, "        oifname %q accept\n", m.cfg.Interface)
	b.WriteString("    }\n\n")

	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type nat hook prerouting priority dstnat; policy accept;\n")
	for _, f := range forwards {
		if !f.Enabled {
			continue
		}
		proto := f.Protocol
		if proto == "" {
			proto = "tcp"
		}
		// The table is `inet`, so nftables requires an explicit address
		// family on dnat. Targets are always IPv4 tunnel peers.
		fmt.Fprintf(&b, "        iifname != %q %s dport %d dnat ip to %s:%d\n",
			m.cfg.Interface, proto, f.PublicPort, f.TargetIP, f.TargetPort)
	}
	b.WriteString("    }\n\n")

	// DNAT alone is not enough: without SNAT the Umbrel peer would try to
	// answer the original client directly (and its default route does not go
	// through the tunnel). Masquerading towards wg0 makes the reply come back
	// to the VPS, which reverses the translation.
	b.WriteString("    chain postrouting {\n")
	b.WriteString("        type nat hook postrouting priority srcnat; policy accept;\n")
	fmt.Fprintf(&b, "        oifname %q masquerade\n", m.cfg.Interface)
	b.WriteString("    }\n")
	b.WriteString("}\n")
	return b.String()
}

// Apply persists and loads the ruleset. It deletes the previous table first so
// the operation is idempotent and no duplicate rules accumulate.
func (m *Manager) Apply(ctx context.Context, forwards []state.Forward) error {
	rules := m.Rules(forwards)
	// Validate from stdin before writing the persisted ruleset. If the rendered
	// rules are invalid the file must stay untouched: umbrel-tunnel-firewall
	// loads it at boot and a broken file would keep the tunnel down.
	if _, err := m.run.RunInput(ctx, []byte(rules), "nft", "-c", "-f", "-"); err != nil {
		return fmt.Errorf("validar nftables: %w", err)
	}
	if err := fsutil.WriteString(m.paths.RulesFile(), rules, 0o644); err != nil {
		return err
	}
	// The table may not exist yet; ignore that error.
	_, _ = m.run.Run(ctx, "nft", "delete", "table", "inet", "umbrel_tunnel")
	if _, err := m.run.Run(ctx, "nft", "-f", m.paths.RulesFile()); err != nil {
		return fmt.Errorf("aplicar nftables: %w", err)
	}
	return nil
}

// Delete removes the table (used by uninstall).
func (m *Manager) Delete(ctx context.Context) error {
	_, err := m.run.Run(ctx, "nft", "delete", "table", "inet", "umbrel_tunnel")
	return err
}
