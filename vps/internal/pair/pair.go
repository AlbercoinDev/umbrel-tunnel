// Package pair implements the ut1 pairing code shared with the Umbrel app.
package pair

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// Prefix identifies a umbrel-tunnel pairing code.
const Prefix = "ut1."

// Pairing is the payload embedded in a ut1 code. It never contains a
// WireGuard private key: the Umbrel app generates its own keypair and
// registers the public key through the authenticated VPS API.
type Pairing struct {
	V            int    `json:"v"`
	API          string `json:"api"`
	Token        string `json:"token"`
	Endpoint     string `json:"endpoint,omitempty"`
	ServerPubKey string `json:"server_pubkey,omitempty"`
	UmbrelIP     string `json:"umbrel_ip,omitempty"`
	Subnet       string `json:"subnet,omitempty"`
	MTU          int    `json:"mtu,omitempty"`
}

// Encode serializes a pairing payload.
func Encode(p Pairing) (string, error) {
	if err := p.validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return Prefix + base64.RawURLEncoding.EncodeToString(data), nil
}

// Decode parses a ut1 code.
func Decode(code string) (Pairing, error) {
	code = strings.TrimSpace(code)
	if !strings.HasPrefix(code, Prefix) {
		return Pairing{}, fmt.Errorf("código inválido: debe empezar por %q", Prefix)
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(code, Prefix))
	if err != nil {
		return Pairing{}, fmt.Errorf("código inválido: %w", err)
	}
	var p Pairing
	if err := json.Unmarshal(data, &p); err != nil {
		return Pairing{}, fmt.Errorf("código inválido: %w", err)
	}
	if err := p.validate(); err != nil {
		return Pairing{}, err
	}
	return p, nil
}

func (p Pairing) validate() error {
	if p.V != 1 {
		return fmt.Errorf("versión de emparejamiento no soportada: %d", p.V)
	}
	u, err := url.Parse(p.API)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("api inválida: %q", p.API)
	}
	if strings.TrimSpace(p.Token) == "" {
		return fmt.Errorf("token vacío")
	}
	if p.Subnet != "" {
		if _, _, err := net.ParseCIDR(p.Subnet); err != nil {
			return fmt.Errorf("subred inválida: %q", p.Subnet)
		}
	}
	if p.UmbrelIP != "" && net.ParseIP(p.UmbrelIP) == nil {
		return fmt.Errorf("IP de Umbrel inválida: %q", p.UmbrelIP)
	}
	if p.MTU != 0 && (p.MTU < 1280 || p.MTU > 1500) {
		return fmt.Errorf("MTU fuera de rango: %d", p.MTU)
	}
	return nil
}

// Block renders a human-friendly pairing summary.
func Block(p Pairing) string {
	var b strings.Builder
	b.WriteString("--- umbrel-tunnel: emparejamiento ---\n")
	fmt.Fprintf(&b, "API:    %s\n", p.API)
	fmt.Fprintf(&b, "Token:  %s\n", p.Token)
	if p.Endpoint != "" {
		fmt.Fprintf(&b, "VPS:    %s\n", p.Endpoint)
	}
	if p.ServerPubKey != "" {
		fmt.Fprintf(&b, "Clave:  %s\n", p.ServerPubKey)
	}
	if code, err := Encode(p); err == nil {
		fmt.Fprintf(&b, "Código: %s\n", code)
	}
	b.WriteString("---------------------------------\n")
	return b.String()
}
