//go:build !linux && !darwin && !windows

package scan

func (s *scanner) checkHomePersistence(_ string) {}

func (s *scanner) checkGlobalPersistence() {}
