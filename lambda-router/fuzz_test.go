package main

import "testing"

func FuzzParsePath(f *testing.F) {
	f.Add("/callback/10.0.1.25/udp")
	f.Add("/callback/192.168.0.1/tcp")
	f.Add("/callback/999.999.999.999/udp")
	f.Add("/callback/2001:db8::1/tcp")
	f.Add("")
	f.Add("/callback/%31%30.0.0.1/udp")

	f.Fuzz(func(t *testing.T, path string) {
		ip, protocol, err := parsePath(path)
		if err != nil {
			return
		}
		if ip == nil || ip.To4() == nil {
			t.Fatalf("parsePath accepted a non-IPv4 address: %v", ip)
		}
		if protocol != "udp" && protocol != "tcp" {
			t.Fatalf("parsePath returned invalid protocol %q", protocol)
		}
	})
}
