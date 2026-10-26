package pair

import (
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Pairing{
		V:            1,
		API:          "http://10.0.0.1:8080",
		Token:        "abc123",
		Endpoint:     "203.0.113.10:51820",
		ServerPubKey: "c2VydmVyLXB1YmxpYy1rZXk=",
		UmbrelIP:     "10.0.0.2",
		Subnet:       "10.0.0.0/24",
		MTU:          1420,
	}
	code, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !strings.HasPrefix(code, Prefix) {
		t.Fatalf("prefijo inesperado: %s", code)
	}
	out, err := Decode(code)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != in {
		t.Fatalf("roundtrip distinto:\n%+v\n%+v", out, in)
	}
}

func TestDecodeRejectsBadCodes(t *testing.T) {
	cases := []string{"", "nope", "tw2.abc", Prefix + "!!!", Prefix + "e30"}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Fatalf("se esperaba error para %q", c)
		}
	}
}

func TestEncodeValidates(t *testing.T) {
	if _, err := Encode(Pairing{V: 2, API: "http://10.0.0.1:8080", Token: "x"}); err == nil {
		t.Fatal("versión inválida aceptada")
	}
	if _, err := Encode(Pairing{V: 1, API: "ftp://x", Token: "x"}); err == nil {
		t.Fatal("api inválida aceptada")
	}
	if _, err := Encode(Pairing{V: 1, API: "http://10.0.0.1:8080"}); err == nil {
		t.Fatal("token vacío aceptado")
	}
	if _, err := Encode(Pairing{V: 1, API: "http://10.0.0.1:8080", Token: "x", Subnet: "10.0.0.0/33"}); err == nil {
		t.Fatal("subred inválida aceptada")
	}
	if _, err := Encode(Pairing{V: 1, API: "http://10.0.0.1:8080", Token: "x", MTU: 9000}); err == nil {
		t.Fatal("MTU inválido aceptado")
	}
}
