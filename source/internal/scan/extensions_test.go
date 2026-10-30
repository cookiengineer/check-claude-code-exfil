package scan

import (
	"path/filepath"
	"testing"
)

func TestExtensionVersionBoundary(t *testing.T) {
	home := t.TempDir()
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.3130-linux-x64", "package.json"),
		`{"name":"claude-code","publisher":"anthropic","version":"2.1.3130"}`+"\n")
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.3130-linux-x64", "extension.js"), "clean\n")

	s := newTestScanner()
	s.checkExtensions(home)
	if reportHasFinding(s.report, "extension-vulnerable-version") {
		t.Fatal("version 2.1.3130 must not match 2.1.313")
	}
}

func TestExtensionVersionMatchWithPlatformSuffix(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.313-win32-x64")
	mustWrite(t, filepath.Join(dir, "package.json"), `{"name":"claude-code","publisher":"anthropic","version":"2.1.313"}`+"\n")
	mustWrite(t, filepath.Join(dir, "extension.js"), "clean\n")

	s := newTestScanner()
	s.checkExtensions(home)
	if !reportHasFinding(s.report, "extension-vulnerable-version") {
		t.Fatalf("expected vulnerable extension finding, got %#v", s.report.Findings)
	}
}
