package scan

import "testing"

func TestParseWindowsProcessJSON(t *testing.T) {
	data := []byte(`[
		{"ProcessId":100,"ParentProcessId":1,"Name":"ssh.exe","CommandLine":"ssh -R \"*:0:localhost:22\" tunnel@134.209.82.225"},
		{"ProcessId":101,"ParentProcessId":1,"Name":"explorer.exe","CommandLine":null}
	]`)
	processes, err := parseWindowsProcessJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 2 {
		t.Fatalf("expected 2 processes, got %d", len(processes))
	}
	if processes[0].PID != 100 || processes[0].PPID != 1 || processes[0].Name != "ssh.exe" {
		t.Fatalf("unexpected first process: %#v", processes[0])
	}
	if processes[1].Command != "" {
		t.Fatalf("expected empty command line, got %q", processes[1].Command)
	}
}

func TestParseWindowsProcessJSONSingleObject(t *testing.T) {
	data := []byte(`{"ProcessId":7,"ParentProcessId":1,"Name":"cmd.exe","CommandLine":"cmd /c sysmon.cmd"}`)
	processes, err := parseWindowsProcessJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 || processes[0].PID != 7 {
		t.Fatalf("unexpected processes: %#v", processes)
	}
}

func TestParseWMICProcessCSV(t *testing.T) {
	data := []byte("Node,CommandLine,Name,ParentProcessId,ProcessId\n" +
		"HOST,\"ssh.exe -R \"\"*:0:localhost:22\"\"\",ssh.exe,4,123\n")
	processes, err := parseWMICProcessCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 {
		t.Fatalf("expected 1 process, got %d", len(processes))
	}
	if processes[0].PID != 123 || processes[0].PPID != 4 || processes[0].Name != "ssh.exe" {
		t.Fatalf("unexpected process: %#v", processes[0])
	}
}

func TestParseWindowsNetstat(t *testing.T) {
	data := `Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:50000        134.209.82.225:22      ESTABLISHED     1234
  TCP    127.0.0.1:50001        127.0.0.1:8099         SYN_SENT        1234
  UDP    0.0.0.0:500           *:*                                    99
`
	connections := parseWindowsNetstat(data)
	if len(connections) != 2 {
		t.Fatalf("expected 2 TCP connections, got %d", len(connections))
	}
	if connections[0].Remote != "134.209.82.225:22" || connections[0].PID != 1234 {
		t.Fatalf("unexpected connection: %#v", connections[0])
	}
	if connections[1].State != "SYN_SENT" {
		t.Fatalf("unexpected state: %#v", connections[1])
	}
}

func TestParseTasklistCSV(t *testing.T) {
	data := []byte(`"ssh.exe","1234","Console","1","10,000 K"` + "\n")
	processes, err := parseTasklistCSV(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(processes) != 1 || processes[0].PID != 1234 || processes[0].Name != "ssh.exe" {
		t.Fatalf("unexpected processes: %#v", processes)
	}
}
