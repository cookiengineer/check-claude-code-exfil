package scan

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type windowsProcessRecord struct {
	ProcessID       int     `json:"ProcessId"`
	ParentProcessID int     `json:"ParentProcessId"`
	Name            string  `json:"Name"`
	CommandLine     *string `json:"CommandLine"`
}

type windowsTCPConn struct {
	Local  string
	Remote string
	State  string
	PID    int
}

func parseWindowsProcessJSON(data []byte) ([]ProcessInfo, error) {
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}

	var records []windowsProcessRecord
	if data[0] == '[' {
		if err := json.Unmarshal(data, &records); err != nil {
			return nil, err
		}
	} else {
		var record windowsProcessRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	processes := make([]ProcessInfo, 0, len(records))
	for _, record := range records {
		command := ""
		if record.CommandLine != nil {
			command = *record.CommandLine
		}
		processes = append(processes, ProcessInfo{
			PID:     record.ProcessID,
			PPID:    record.ParentProcessID,
			Name:    record.Name,
			Command: command,
		})
	}
	return processes, nil
}

func parseWMICProcessCSV(data []byte) ([]ProcessInfo, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	header := make(map[string]int)
	var processes []ProcessInfo
	for _, record := range records {
		if len(record) == 0 {
			continue
		}
		if len(header) == 0 {
			for index, field := range record {
				header[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(field, "\ufeff")))] = index
			}
			continue
		}
		get := func(name string) string {
			index, ok := header[name]
			if !ok || index >= len(record) {
				return ""
			}
			return strings.TrimSpace(record[index])
		}
		pid, _ := strconv.Atoi(get("processid"))
		ppid, _ := strconv.Atoi(get("parentprocessid"))
		if pid == 0 {
			continue
		}
		processes = append(processes, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    get("name"),
			Command: get("commandline"),
		})
	}
	if len(header) == 0 {
		return nil, fmt.Errorf("WMIC output did not contain a header")
	}
	return processes, nil
}

func parseTasklistCSV(data []byte) ([]ProcessInfo, error) {
	reader := csv.NewReader(bytes.NewReader(data))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	var processes []ProcessInfo
	for _, record := range records {
		if len(record) < 2 {
			continue
		}
		pid, parseErr := strconv.Atoi(strings.TrimSpace(record[1]))
		if parseErr != nil {
			continue
		}
		processes = append(processes, ProcessInfo{
			PID:  pid,
			Name: strings.TrimSpace(record[0]),
		})
	}
	return processes, nil
}

func parseWindowsNetstat(data string) []windowsTCPConn {
	var connections []windowsTCPConn
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.EqualFold(fields[0], "TCP") {
			continue
		}
		pid, _ := strconv.Atoi(fields[4])
		connections = append(connections, windowsTCPConn{
			Local:  fields[1],
			Remote: fields[2],
			State:  fields[3],
			PID:    pid,
		})
	}
	return connections
}

func splitWindowsAddress(address string) (host string, port string, ok bool) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", false
	}
	return host, port, true
}

func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsed := net.ParseIP(strings.Trim(host, "[]"))
	return parsed != nil && parsed.IsLoopback()
}
