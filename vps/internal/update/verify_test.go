package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func signedServer(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, binary []byte) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256(binary)
	sums := []byte(fmt.Sprintf("%s  umbrel-tunnel-linux-%s\n", hex.EncodeToString(sum[:]), runtime.GOARCH))
	signature := ed25519.Sign(priv, sums)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			_, _ = w.Write(sums)
		case "/SHA256SUMS.sig":
			_, _ = w.Write(signature)
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestVerifyInstalledAcceptsMatchingBinary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("#!/bin/sh\necho 0.6.4\n")
	server := signedServer(t, pub, priv, binary)
	defer server.Close()
	exe := filepath.Join(t.TempDir(), "umbrel-tunnel")
	if err := os.WriteFile(exe, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledWith(context.Background(), "0.6.4", exe, server.URL, pub); err != nil {
		t.Fatalf("binario válido rechazado: %v", err)
	}
}

func TestVerifyInstalledRejectsTamperedBinary(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("#!/bin/sh\necho 0.6.4\n")
	server := signedServer(t, pub, priv, binary)
	defer server.Close()
	exe := filepath.Join(t.TempDir(), "umbrel-tunnel")
	if err := os.WriteFile(exe, append(binary, 'x'), 0o755); err != nil {
		t.Fatal(err)
	}
	err = verifyInstalledWith(context.Background(), "0.6.4", exe, server.URL, pub)
	if !errors.Is(err, ErrChecksum) {
		t.Fatalf("se esperaba ErrChecksum: %v", err)
	}
}

func TestVerifyInstalledRejectsBadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("binario")
	server := signedServer(t, pub, other, binary)
	defer server.Close()
	exe := filepath.Join(t.TempDir(), "umbrel-tunnel")
	if err := os.WriteFile(exe, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	err = verifyInstalledWith(context.Background(), "0.6.4", exe, server.URL, pub)
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("se esperaba ErrSignature: %v", err)
	}
}

func TestVerifyInstalledRejectsDevelopmentBuilds(t *testing.T) {
	if err := VerifyInstalled(context.Background(), "dev", "/bin/true", ""); err == nil {
		t.Fatal("una versión de desarrollo no debe validar")
	}
}
