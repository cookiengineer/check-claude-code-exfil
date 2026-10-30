package scan

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"check-claude-code-exfil/internal/ioc"
)

func TestParseAuthorizedKeyFingerprint(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(sshTestString([]byte("ssh-ed25519")), sshTestString(publicKey)...)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + ioc.VictimKeyComment

	keyType, parsedBlob, comment, err := parseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if keyType != "ssh-ed25519" {
		t.Fatalf("unexpected key type %q", keyType)
	}
	if comment != ioc.VictimKeyComment {
		t.Fatalf("unexpected comment %q", comment)
	}

	sum := sha256.Sum256(blob)
	want := "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
	if got := sshFingerprint(parsedBlob); got != want {
		t.Fatalf("fingerprint mismatch: got %q want %q", got, want)
	}
}

func TestOpenSSHPrivateKeyPublicBlob(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicBlob := append(sshTestString([]byte("ssh-ed25519")), sshTestString(publicKey)...)

	raw := append([]byte(opensshKeyV1Magic), sshTestString([]byte("none"))...)
	raw = append(raw, sshTestString([]byte("none"))...)
	raw = append(raw, sshTestString(nil)...)
	raw = append(raw, sshTestUint32(1)...)
	raw = append(raw, sshTestString(publicBlob)...)
	raw = append(raw, sshTestString([]byte("private-section"))...)

	pem := opensshPrivateKeyHeader + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n" +
		opensshPrivateKeyFooter + "\n"

	parsed, err := opensshPrivateKeyPublicBlob([]byte(pem))
	if err != nil {
		t.Fatal(err)
	}
	if base64.StdEncoding.EncodeToString(parsed) != base64.StdEncoding.EncodeToString(publicBlob) {
		t.Fatal("parsed public key blob does not match")
	}
}

func TestInspectKeyFile(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicBlob := append(sshTestString([]byte("ssh-ed25519")), sshTestString(publicKey)...)

	raw := append([]byte(opensshKeyV1Magic), sshTestString([]byte("none"))...)
	raw = append(raw, sshTestString([]byte("none"))...)
	raw = append(raw, sshTestString(nil)...)
	raw = append(raw, sshTestUint32(1)...)
	raw = append(raw, sshTestString(publicBlob)...)
	raw = append(raw, sshTestString([]byte("private-section"))...)

	pem := opensshPrivateKeyHeader + "\n" +
		base64.StdEncoding.EncodeToString(raw) + "\n" +
		opensshPrivateKeyFooter + "\n"
	pem += "# " + ioc.TunnelKeyComment + "\n"

	path := filepath.Join(t.TempDir(), ".smtk")
	if err := os.WriteFile(path, []byte(pem), 0o600); err != nil {
		t.Fatal(err)
	}
	inspection, err := inspectKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.TunnelComment {
		t.Fatal("expected tunnel key comment to be detected")
	}
	if inspection.TunnelFingerprint {
		t.Fatal("generated test key unexpectedly matches the tunnel fingerprint")
	}
	if inspection.Fingerprint == "" {
		t.Fatal("expected a fingerprint to be computed")
	}
}

func sshTestString(value []byte) []byte {
	result := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(result[:4], uint32(len(value)))
	copy(result[4:], value)
	return result
}

func sshTestUint32(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}
