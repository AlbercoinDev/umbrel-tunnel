package doctor

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"umbrel-tunnel/internal/execx"
	"umbrel-tunnel/internal/state"
)

func TestRequiredPortsFollowAccessMode(t *testing.T) {
	forwards := []state.Forward{
		{AccessMode: "https", PublicPort: 443, Enabled: true},
		{AccessMode: "tls", PublicPort: 50002, Enabled: true},
		{AccessMode: "http", PublicPort: 8080, Enabled: true},
		{AccessMode: "tls", PublicPort: 50003, Enabled: false},
		{PublicPort: 1234, Enabled: true},
	}
	got := requiredPorts(forwards)
	want := []int{80, 443, 8080, 50002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("puertos: %v, esperado %v", got, want)
	}
	if len(requiredPorts(nil)) != 0 {
		t.Fatal("sin publicaciones no debería requerir puertos")
	}
}

func TestHasBindCapability(t *testing.T) {
	if hasBindCapability([]byte("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE")) != true {
		t.Fatal("no detectó la capability")
	}
	if hasBindCapability([]byte("CapabilityBoundingSet=CAP_NET_ADMIN")) {
		t.Fatal("falso positivo")
	}
}

func TestPortBoundUsesSocketState(t *testing.T) {
	run := &execx.Fake{Outputs: map[string][]byte{
		"ss -H -ltn sport = :80": []byte("LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*\n"),
	}}
	if !portBound(context.Background(), run, 80) {
		t.Fatal("debería detectar el puerto en escucha")
	}
	if portBound(context.Background(), run, 443) {
		t.Fatal("no debería inventar un puerto cerrado")
	}
	failing := &execx.Fake{Errors: map[string]error{"ss -H -ltn sport = :80": fmt.Errorf("no ss")}}
	if portBound(context.Background(), failing, 80) {
		t.Fatal("un error de ss no es un puerto abierto")
	}
}
