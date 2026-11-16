package update

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
)

// release-signing.pub.pem is the Ed25519 key that signs SHA256SUMS in every
// release. It is embedded so a compromised download server or GitHub release
// cannot swap both the binary and its checksum unnoticed. The private key is
// kept offline and only used by the release workflow.
//
//go:embed release-signing.pub.pem
var embeddedPubKey []byte

var errNoSignature = fmt.Errorf(
	"la release no trae SHA256SUMS.sig; usa --allow-unsigned-checksum solo si confías en el origen",
)

func isURL(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func parsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("clave pública de release inválida")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("clave pública de release: %w", err)
	}
	ed, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("la clave de release no es Ed25519")
	}
	return ed, nil
}

func verifySignature(pub ed25519.PublicKey, message, signature []byte) error {
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("firma de release con tamaño inválido")
	}
	if !ed25519.Verify(pub, message, signature) {
		return fmt.Errorf("firma de release inválida: SHA256SUMS no coincide con la clave")
	}
	return nil
}

// checksumFor finds the hash of name inside a SHA256SUMS file.
func checksumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		file := strings.TrimPrefix(fields[1], "*")
		if path.Base(file) == name && len(fields[0]) == 64 {
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("%s no aparece en SHA256SUMS", name)
}

// signedChecksum downloads SHA256SUMS and its signature from the release next
// to source, verifies the signature and returns the expected hash.
func signedChecksum(ctx context.Context, source string) (string, error) {
	if !isURL(source) {
		return "", errNoSignature
	}
	base := source[:strings.LastIndex(source, "/")]
	name := path.Base(source)
	sums, err := download(ctx, base+"/SHA256SUMS")
	if err != nil {
		return "", fmt.Errorf("descargar SHA256SUMS: %w", err)
	}
	signature, err := download(ctx, base+"/SHA256SUMS.sig")
	if err != nil {
		return "", errNoSignature
	}
	pub, err := parsePublicKey(embeddedPubKey)
	if err != nil {
		return "", err
	}
	if err := verifySignature(pub, sums, signature); err != nil {
		return "", err
	}
	return checksumFor(sums, name)
}
