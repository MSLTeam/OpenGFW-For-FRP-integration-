package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

func TestTCPProxyDetectsSOCKS5(t *testing.T) {
	s := &tcpStream{reqBuf: &utils.ByteBuffer{}, cfg: defaultFeatureConfig(), gray: true}
	u, done := s.Feed(false, true, false, 0, []byte{0x05, 0x02, 0x00, 0x02})
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if !done {
		t.Fatal("expected stream done")
	}
	if got := u.M["protocol"]; got != "socks5" {
		t.Fatalf("protocol = %v, want socks5", got)
	}
}

func TestTCPProxyDetectsHTTPConnect(t *testing.T) {
	s := &tcpStream{reqBuf: &utils.ByteBuffer{}, cfg: defaultFeatureConfig(), gray: true}
	payload := []byte("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	u, done := s.Feed(false, true, false, 0, payload)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if !done {
		t.Fatal("expected stream done")
	}
	if got := u.M["protocol"]; got != "http_connect" {
		t.Fatalf("protocol = %v, want http_connect", got)
	}
	if got := u.M["target_host"]; got != "example.com" {
		t.Fatalf("target_host = %v, want example.com", got)
	}
	if got := u.M["target_port"]; got != 443 {
		t.Fatalf("target_port = %v, want 443", got)
	}
}

func TestTCPProxyDetectsEncryptedCandidate(t *testing.T) {
	s := &tcpStream{reqBuf: &utils.ByteBuffer{}, cfg: defaultFeatureConfig(), gray: true}
	payload := makeHighEntropyPayload(256)
	u, done := s.Feed(false, true, false, 0, payload)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if !done {
		t.Fatal("expected stream done")
	}
	if got := u.M["protocol"]; got != "shadowsocks_vmess_like" {
		t.Fatalf("protocol = %v, want shadowsocks_vmess_like", got)
	}
	candidates, ok := u.M["candidates"].([]string)
	if !ok || !containsString(candidates, "shadowsocks") || !containsString(candidates, "vmess") {
		t.Fatalf("candidates = %v, want contains shadowsocks/vmess", u.M["candidates"])
	}
}

func TestTCPProxyDetectsSSHBanner(t *testing.T) {
	s := &tcpStream{reqBuf: &utils.ByteBuffer{}, cfg: defaultFeatureConfig(), gray: true}
	payload := []byte("SSH-2.0-OpenSSH_9.7\r\n")
	u, done := s.Feed(false, true, false, 0, payload)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if !done {
		t.Fatal("expected stream done")
	}
	if got := u.M["protocol"]; got != "ssh_tunnel" {
		t.Fatalf("protocol = %v, want ssh_tunnel", got)
	}
	if got := u.M["ssh_software"]; got != "OpenSSH_9.7" {
		t.Fatalf("ssh_software = %v, want OpenSSH_9.7", got)
	}
}

func TestUDPProxyDetectsSOCKS5Relay(t *testing.T) {
	s := &udpStream{cfg: defaultFeatureConfig(), gray: true}
	packet := []byte{
		0x00, 0x00, 0x00, 0x01,
		1, 2, 3, 4,
		0x01, 0xbb,
		'h', 'i',
	}
	u, done := s.Feed(false, packet)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if done {
		t.Fatal("did not expect stream done")
	}
	if got := u.M["protocol"]; got != "socks5_udp_relay" {
		t.Fatalf("protocol = %v, want socks5_udp_relay", got)
	}
	if got := u.M["dst_addr"]; got != "1.2.3.4" {
		t.Fatalf("dst_addr = %v, want 1.2.3.4", got)
	}
	if got := u.M["dst_port"]; got != 443 {
		t.Fatalf("dst_port = %v, want 443", got)
	}
}

func TestUDPProxyDetectsWireGuard(t *testing.T) {
	s := &udpStream{cfg: defaultFeatureConfig(), gray: true}
	packet := make([]byte, 148)
	packet[0] = 1
	u, done := s.Feed(false, packet)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if done {
		t.Fatal("did not expect stream done")
	}
	if got := u.M["protocol"]; got != "wireguard" {
		t.Fatalf("protocol = %v, want wireguard", got)
	}
}

func TestUDPProxyDetectsOpenVPN(t *testing.T) {
	s := &udpStream{cfg: defaultFeatureConfig(), gray: true}
	packet := []byte{openVPNControlHardResetClientV2 << 3, 0x00, 0x00, 0x00}
	u, done := s.Feed(false, packet)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if done {
		t.Fatal("did not expect stream done")
	}
	if got := u.M["protocol"]; got != "openvpn_udp" {
		t.Fatalf("protocol = %v, want openvpn_udp", got)
	}
}

func TestUDPProxyDetectsEncryptedCandidate(t *testing.T) {
	s := &udpStream{cfg: defaultFeatureConfig(), gray: true}
	packet := makeHighEntropyPayload(256)
	u, done := s.Feed(false, packet)
	if u == nil {
		t.Fatal("expected update, got nil")
	}
	if done {
		t.Fatal("did not expect stream done")
	}
	if got := u.M["protocol"]; got != "shadowsocks_vmess_like_udp" {
		t.Fatalf("protocol = %v, want shadowsocks_vmess_like_udp", got)
	}
}

func TestProxyGraySamplingSuppressesOutput(t *testing.T) {
	s := &tcpStream{reqBuf: &utils.ByteBuffer{}, cfg: defaultFeatureConfig(), gray: false}
	u, done := s.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if !done {
		t.Fatal("expected stream done")
	}
	if u != nil {
		t.Fatalf("expected nil update in gray-off mode, got %v", u)
	}
}

func TestSourcePenaltyCrossConnectionBlock(t *testing.T) {
	pa := NewProxyAnalyzer()
	src := net.IPv4(10, 0, 0, 1)

	s1 := pa.NewTCP(analyzer.TCPInfo{SrcIP: src}, nil)
	u1, done1 := s1.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if u1 == nil || !done1 {
		t.Fatalf("expected first flow detected and done, got u=%v done=%v", u1, done1)
	}

	s2 := pa.NewTCP(analyzer.TCPInfo{SrcIP: src}, nil)
	u2, done2 := s2.Feed(false, true, false, 0, []byte("GET / HTTP/1.1\r\n\r\n"))
	if u2 == nil || !done2 {
		t.Fatalf("expected second flow blocked by penalty, got u=%v done=%v", u2, done2)
	}
	if got := u2.M["protocol"]; got != "source_ip_penalty" {
		t.Fatalf("protocol = %v, want source_ip_penalty", got)
	}
}

func TestSourcePenaltyTTLExpiry(t *testing.T) {
	pa := NewProxyAnalyzer()
	src := net.IPv4(10, 0, 0, 2)

	s1 := pa.NewTCP(analyzer.TCPInfo{SrcIP: src}, nil)
	_, _ = s1.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})

	pa.penalty.mu.Lock()
	pa.penalty.entries[src.String()] = time.Now().Add(-time.Second)
	pa.penalty.mu.Unlock()

	s2 := pa.NewTCP(analyzer.TCPInfo{SrcIP: src}, nil)
	u2, done2 := s2.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if u2 == nil || !done2 {
		t.Fatalf("expected normal detection after expiry, got u=%v done=%v", u2, done2)
	}
	if got := u2.M["protocol"]; got == "source_ip_penalty" {
		t.Fatalf("unexpected penalty protocol after expiry")
	}
}

func makeHighEntropyPayload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(0x80 + (i % 128))
	}
	return p
}

func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}
