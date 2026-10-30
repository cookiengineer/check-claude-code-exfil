package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"check-claude-code-exfil/internal/ioc"
)

const (
	opensshPrivateKeyHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"
	opensshPrivateKeyFooter = "-----END OPENSSH PRIVATE KEY-----"
	opensshKeyV1Magic       = "openssh-key-v1\x00"
)

type keyFileInspection struct {
	Fingerprint       string
	TunnelFingerprint bool
	VictimFingerprint bool
	TunnelComment     bool
	VictimComment     bool
	ServerIP          bool
	MatchedTokens     []string
}

func (s *scanner) checkSSH(home string) {
	path := filepath.Join(home, ".ssh", "authorized_keys")
	data, err := readFileLimited(path, maxTextFileSize)
	if err != nil {
		if os.IsNotExist(err) {
			return
		}
		s.addWarning(Warning{
			Check:      "ssh",
			Path:       path,
			Message:    fmt.Sprintf("cannot read authorized_keys: %v", err),
			Incomplete: true,
		})
		return
	}

	for index, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		_, blob, comment, parseErr := parseAuthorizedKey(line)
		if parseErr == nil {
			fingerprint := sshFingerprint(blob)
			if fingerprint == ioc.VictimKeyFingerprint {
				s.addFinding(Finding{
					ID:          "ssh-victim-key",
					Severity:    SeverityCritical,
					Category:    "ssh",
					Title:       "Attacker SSH victim-login public key found",
					Detail:      "The authorized_keys entry matches the public key fingerprint documented in the advisory.",
					Path:        path,
					Line:        index + 1,
					Fingerprint: fingerprint,
					Evidence:    joinEvidence("comment="+comment, "fingerprint="+fingerprint),
				})
				continue
			}
		}

		switch {
		case containsFold(line, ioc.TunnelKeyComment):
			s.addFinding(Finding{
				ID:       "ssh-tunnel-key-comment",
				Severity: SeverityCritical,
				Category: "ssh",
				Title:    "Attacker tunnel-key comment found in authorized_keys",
				Detail:   "The authorized_keys entry references the tunnel key comment documented in the advisory.",
				Path:     path,
				Line:     index + 1,
				Evidence: "comment=" + ioc.TunnelKeyComment,
			})
		case containsFold(line, ioc.VictimKeyComment):
			s.addFinding(Finding{
				ID:       "ssh-victim-key-comment",
				Severity: SeverityWarning,
				Category: "ssh",
				Title:    "Suspicious attacker key comment found in authorized_keys",
				Detail:   "The key comment matches the advisory. Verify the key fingerprint rather than relying on the comment alone.",
				Path:     path,
				Line:     index + 1,
				Evidence: "comment=" + ioc.VictimKeyComment,
			})
		}
	}
}

func parseAuthorizedKey(line string) (keyType string, blob []byte, comment string, err error) {
	fields := strings.Fields(line)
	for index, field := range fields {
		if !looksLikeSSHKeyType(field) {
			continue
		}
		if index+1 >= len(fields) {
			return "", nil, "", fmt.Errorf("missing key data after %q", field)
		}
		decoded, decodeErr := decodeSSHBase64(fields[index+1])
		if decodeErr != nil {
			continue
		}
		keyComment := ""
		if index+2 < len(fields) {
			keyComment = strings.Join(fields[index+2:], " ")
		}
		return field, decoded, keyComment, nil
	}
	return "", nil, "", fmt.Errorf("no SSH public key found")
}

func looksLikeSSHKeyType(value string) bool {
	for _, prefix := range []string{"ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-"} {
		if strings.HasPrefix(value, prefix) && !strings.Contains(value, "=") {
			return true
		}
	}
	return false
}

func decodeSSHBase64(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.DecodeString(value)
}

func sshFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func opensshPrivateKeyPublicBlob(data []byte) ([]byte, error) {
	text := string(data)
	begin := strings.Index(text, opensshPrivateKeyHeader)
	if begin < 0 {
		return nil, fmt.Errorf("not an OpenSSH private key")
	}
	begin += len(opensshPrivateKeyHeader)
	end := strings.Index(text[begin:], opensshPrivateKeyFooter)
	if end < 0 {
		return nil, fmt.Errorf("missing OpenSSH private key footer")
	}
	encoded := text[begin : begin+end]
	encoded = strings.NewReplacer("\r", "", "\n", "", "\t", "", " ", "").Replace(encoded)
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(raw, []byte(opensshKeyV1Magic)) {
		return nil, fmt.Errorf("unsupported OpenSSH private key format")
	}

	offset := len(opensshKeyV1Magic)
	if _, offset, err = readSSHString(raw, offset); err != nil {
		return nil, err
	}
	if _, offset, err = readSSHString(raw, offset); err != nil {
		return nil, err
	}
	if _, offset, err = readSSHString(raw, offset); err != nil {
		return nil, err
	}
	if offset+4 > len(raw) {
		return nil, fmt.Errorf("truncated OpenSSH private key")
	}
	count := binary.BigEndian.Uint32(raw[offset : offset+4])
	offset += 4
	if count == 0 {
		return nil, fmt.Errorf("OpenSSH private key contains no keys")
	}
	publicBlob, _, err := readSSHString(raw, offset)
	if err != nil {
		return nil, err
	}
	return publicBlob, nil
}

func readSSHString(data []byte, offset int) ([]byte, int, error) {
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("truncated SSH string length")
	}
	length := int(binary.BigEndian.Uint32(data[offset : offset+4]))
	offset += 4
	if length < 0 || offset+length > len(data) {
		return nil, offset, fmt.Errorf("truncated SSH string")
	}
	return data[offset : offset+length], offset + length, nil
}

func inspectKeyFile(path string) (keyFileInspection, error) {
	data, err := readFileLimited(path, maxTextFileSize)
	if err != nil {
		return keyFileInspection{}, err
	}
	content := string(data)
	inspection := keyFileInspection{
		TunnelComment: containsFold(content, ioc.TunnelKeyComment),
		VictimComment: containsFold(content, ioc.VictimKeyComment),
		ServerIP:      strings.Contains(content, ioc.TunnelServer),
		MatchedTokens: matchedArtifactTokens(content),
	}

	if blob, parseErr := opensshPrivateKeyPublicBlob(data); parseErr == nil {
		inspection.Fingerprint = sshFingerprint(blob)
		inspection.TunnelFingerprint = inspection.Fingerprint == ioc.TunnelKeyFingerprint
		inspection.VictimFingerprint = inspection.Fingerprint == ioc.VictimKeyFingerprint
	}
	return inspection, nil
}
