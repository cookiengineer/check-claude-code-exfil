//go:build linux

package scan

import "testing"

func TestParseProcAddressIPv4(t *testing.T) {
	host, port, ok := parseProcAddress("E152D186:0016")
	if !ok {
		t.Fatal("expected address to parse")
	}
	if host != "134.209.82.225" {
		t.Fatalf("unexpected host %q", host)
	}
	if port != "22" {
		t.Fatalf("unexpected port %q", port)
	}
}

func TestParseProcAddressIPv6Loopback(t *testing.T) {
	host, port, ok := parseProcAddress("00000000000000000000000001000000:1F91")
	if !ok {
		t.Fatal("expected address to parse")
	}
	if host != "::1" {
		t.Fatalf("unexpected host %q", host)
	}
	if port != "8081" {
		t.Fatalf("unexpected port %q", port)
	}
}

func TestTCPStateName(t *testing.T) {
	if got := tcpStateName("01"); got != "ESTABLISHED" {
		t.Fatalf("unexpected state %q", got)
	}
	if got := tcpStateName("0A"); got != "LISTEN" {
		t.Fatalf("unexpected state %q", got)
	}
}
