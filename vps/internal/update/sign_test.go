package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
)

func TestVerifySignatureAcceptsAndRejects(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("hash  umbrel-tunnel-linux-amd64\n")
	signature := ed25519.Sign(priv, message)
	if err := verifySignature(pub, message, signature); err != nil {
		t.Fatalf("firma válida rechazada: %v", err)
	}
	if err := verifySignature(pub, append(message, 'x'), signature); err == nil {
		t.Fatal("se aceptó una firma sobre otro mensaje")
	}
	if err := verifySignature(pub, message, signature[:len(signature)-1]); err == nil {
		t.Fatal("se aceptó una firma truncada")
	}
}

func TestChecksumForFindsArchitecture(t *testing.T) {
	sums := []byte(
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  umbrel-tunnel-1.6.3-linux-amd64.tar.gz\n" +
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  umbrel-tunnel-linux-amd64\n",
	)
	got, err := checksumFor(sums, "umbrel-tunnel-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	want := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if got != want {
		t.Fatalf("%s != %s", got, want)
	}
	if _, err := checksumFor(sums, "otro-binario"); err == nil {
		t.Fatal("se aceptó un binario que no está en SHA256SUMS")
	}
}

func TestEmbeddedKeyMatchesRepositoryFile(t *testing.T) {
	repository, err := os.ReadFile("../../release-signing.pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(repository), bytes.TrimSpace(embeddedPubKey)) {
		t.Fatal("la clave embebida no coincide con vps/release-signing.pub.pem")
	}
	if _, err := parsePublicKey(embeddedPubKey); err != nil {
		t.Fatal(err)
	}
}

func TestUnsignedReleaseFailsClosed(t *testing.T) {
	// A release without SHA256SUMS.sig must not install by default.
	if isURL("http://example.invalid/bin") != true {
		t.Fatal("isURL")
	}
	if _, err := signedChecksum(context.Background(), "http://127.0.0.1:1/bin"); err == nil {
		t.Fatal("una release sin firma no debe validar")
	}
}
