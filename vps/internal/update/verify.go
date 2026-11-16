package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
)

var (
	// ErrSignature means SHA256SUMS did not verify with the embedded key.
	ErrSignature = errors.New("firma de release inválida")
	// ErrChecksum means the running binary is not the one in the signed list.
	ErrChecksum = errors.New("checksum del binario instalado no coincide")
)

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// VerifyInstalled proves that the running executable matches the signed
// SHA256SUMS of its release. It is the supply-chain check used by `doctor`.
func VerifyInstalled(ctx context.Context, version, exe, base string) error {
	pub, err := parsePublicKey(embeddedPubKey)
	if err != nil {
		return err
	}
	return verifyInstalledWith(ctx, version, exe, base, pub)
}

func verifyInstalledWith(
	ctx context.Context,
	version, exe, base string,
	pub ed25519.PublicKey,
) error {
	if version == "" || version == "dev" {
		return fmt.Errorf("versión de desarrollo: no hay release firmada que verificar")
	}
	if base == "" {
		base = fmt.Sprintf("https://github.com/%s/releases/download/v%s", repo, version)
	}
	sums, err := download(ctx, base+"/SHA256SUMS")
	if err != nil {
		return fmt.Errorf("descargar SHA256SUMS: %w", err)
	}
	signature, err := download(ctx, base+"/SHA256SUMS.sig")
	if err != nil {
		return fmt.Errorf("descargar SHA256SUMS.sig: %w", err)
	}
	if err := verifySignature(pub, sums, signature); err != nil {
		return fmt.Errorf("%w: %v", ErrSignature, err)
	}
	name := "umbrel-tunnel-linux-" + runtime.GOARCH
	want, err := checksumFor(sums, name)
	if err != nil {
		return err
	}
	got, err := hashFile(exe)
	if err != nil {
		return fmt.Errorf("leer el binario instalado: %w", err)
	}
	if got != want {
		return fmt.Errorf("%w: esperado %s, obtenido %s", ErrChecksum, want, got)
	}
	return nil
}
