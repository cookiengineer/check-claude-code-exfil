//go:build !linux && !darwin && !windows

package scan

import "fmt"

func listProcesses() ([]ProcessInfo, []Warning, error) {
	return nil, nil, fmt.Errorf("process enumeration is not supported on this platform")
}
