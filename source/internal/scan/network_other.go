//go:build !linux && !darwin && !windows

package scan

import "fmt"

func (s *scanner) scanNetwork() {
	s.addWarning(Warning{
		Check:      "network",
		Message:    fmt.Sprintf("network inspection is not supported on %s", "this platform"),
		Incomplete: true,
	})
}
