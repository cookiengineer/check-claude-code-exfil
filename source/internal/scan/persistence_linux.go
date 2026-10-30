//go:build linux

package scan

func (s *scanner) checkHomePersistence(home string) {
	s.checkCronHome(home)
}

func (s *scanner) checkGlobalPersistence() {}
