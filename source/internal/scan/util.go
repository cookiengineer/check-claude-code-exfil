package scan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf16"

	"check-claude-code-exfil/internal/ioc"
)

const maxTextFileSize = 16 << 20

var artifactTokens = []string{
	strings.ToLower(ioc.VictimKeyComment),
	strings.ToLower(ioc.TunnelKeyComment),
	strings.ToLower(ioc.TunnelServer),
	".config/.smt",
	".config\\.smt",
	".smtk",
	"smt.cmd",
	"sysmon.cmd",
	".stk_",
	strings.ToLower(ioc.RemoteForwardPattern),
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file is larger than the %d byte scan limit", limit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}

func matchedArtifactTokens(content string) []string {
	lower := strings.ToLower(content)
	seen := make(map[string]struct{})
	var matches []string
	for _, token := range artifactTokens {
		if token == "" {
			continue
		}
		if strings.Contains(lower, token) {
			if _, ok := seen[token]; ok {
				continue
			}
			seen[token] = struct{}{}
			matches = append(matches, token)
		}
	}
	return matches
}

func normalizeTextOutput(data []byte) []byte {
	if len(data) >= 3 && data[0] == 0xef && data[1] == 0xbb && data[2] == 0xbf {
		data = data[3:]
	}
	if len(data) >= 2 {
		switch {
		case data[0] == 0xff && data[1] == 0xfe:
			return decodeUTF16(data[2:], binary.LittleEndian)
		case data[0] == 0xfe && data[1] == 0xff:
			return decodeUTF16(data[2:], binary.BigEndian)
		}
	}
	return data
}

func decodeUTF16(data []byte, order binary.ByteOrder) []byte {
	values := make([]uint16, 0, len(data)/2)
	for index := 0; index+1 < len(data); index += 2 {
		values = append(values, order.Uint16(data[index:index+2]))
	}
	return []byte(string(utf16.Decode(values)))
}

func joinEvidence(values ...string) string {
	var nonEmpty []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			nonEmpty = append(nonEmpty, value)
		}
	}
	return strings.Join(nonEmpty, ", ")
}
