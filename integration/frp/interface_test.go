package frp

import (
	"net"
	"testing"
)

func TestTCPProxyDecisionBlockAndWarn(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	blockStream, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		SrcPort: 50000,
		DstPort: 1080,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	rep := blockStream.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if rep.Action != ActionBlock {
		t.Fatalf("action = %s, want block", rep.Action)
	}
	if rep.Proxy == nil || rep.Proxy.Protocol != "socks5" {
		t.Fatalf("proxy = %+v, want protocol socks5", rep.Proxy)
	}
	if rep.Traffic == nil || rep.Traffic.Family != "proxy" {
		t.Fatalf("traffic = %+v, want family proxy", rep.Traffic)
	}

	warnStream, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 0, 3),
		DstIP:   net.IPv4(10, 0, 0, 4),
		SrcPort: 50001,
		DstPort: 6022,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	rep = warnStream.Feed(false, true, false, 0, []byte("SSH-2.0-OpenSSH_9.7\r\n"))
	if rep.Action != ActionWarn {
		t.Fatalf("action = %s, want warn", rep.Action)
	}
	if rep.Proxy == nil || rep.Proxy.Protocol != "ssh_tunnel" {
		t.Fatalf("proxy = %+v, want protocol ssh_tunnel", rep.Proxy)
	}
}

func TestSourcePenaltyCrossConnection(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	meta := StreamMeta{
		SrcIP:   net.IPv4(10, 0, 1, 1),
		DstIP:   net.IPv4(10, 0, 1, 2),
		SrcPort: 50002,
		DstPort: 1080,
	}

	s1, err := engine.NewTCPStream(meta)
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	r1 := s1.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if r1.Action != ActionBlock {
		t.Fatalf("first action = %s, want block", r1.Action)
	}

	s2, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 1, 1), // same source ip
		DstIP:   net.IPv4(10, 0, 1, 3),
		SrcPort: 50003,
		DstPort: 80,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	r2 := s2.Feed(false, true, false, 0, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if r2.Action != ActionBlock {
		t.Fatalf("second action = %s, want block", r2.Action)
	}
	if r2.Proxy == nil || r2.Proxy.Protocol != "source_ip_penalty" {
		t.Fatalf("second proxy = %+v, want protocol source_ip_penalty", r2.Proxy)
	}
}

func TestSessionManager(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	m := NewSessionManager(engine)
	meta := StreamMeta{
		SrcIP:   net.IPv4(10, 0, 2, 1),
		DstIP:   net.IPv4(10, 0, 2, 2),
		SrcPort: 50004,
		DstPort: 25565,
	}

	r, err := m.FeedTCP("s1", meta, false, true, false, 0, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("feed tcp: %v", err)
	}
	if r.Action == "" {
		t.Fatal("expected action in report")
	}
	_, ok := m.CloseTCP("s1", false)
	if !ok {
		t.Fatal("expected close tcp stream exists")
	}
}

func TestProxyPolicyDefaultsAndDisable(t *testing.T) {
	engine, err := NewEngine(Config{})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if !engine.proxyPolicy.Enabled || engine.proxyPolicy.HighThreshold != 85 || engine.proxyPolicy.MediumThreshold != 70 {
		t.Fatalf("unexpected default policy: %+v", engine.proxyPolicy)
	}
	if !engine.trafficPolicy.Enabled || !engine.trafficPolicy.BlockWebTCP {
		t.Fatalf("unexpected default traffic policy: %+v", engine.trafficPolicy)
	}

	engine.SetProxyPolicy(ProxyPolicy{Enabled: false})
	if engine.proxyPolicy.Enabled {
		t.Fatalf("policy should be disabled: %+v", engine.proxyPolicy)
	}
	if engine.proxyPolicy.HighThreshold != 85 || engine.proxyPolicy.MediumThreshold != 70 {
		t.Fatalf("unexpected normalized thresholds: %+v", engine.proxyPolicy)
	}
}

func TestTrafficPolicyBlockWebTCPHTTP(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	stream, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 3, 1),
		DstIP:   net.IPv4(10, 0, 3, 2),
		SrcPort: 50010,
		DstPort: 80,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	rep := stream.Feed(false, true, false, 0, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if rep.Action != ActionBlock {
		t.Fatalf("action = %s, want block", rep.Action)
	}
	if rep.Reason != "traffic policy block web tcp" {
		t.Fatalf("reason = %s, want traffic policy block web tcp", rep.Reason)
	}
	if rep.Traffic == nil || rep.Traffic.Family != "web" || rep.Traffic.Transport != "tcp" {
		t.Fatalf("traffic = %+v, want web/tcp", rep.Traffic)
	}
}

func TestTrafficPolicyBlockWebTCPTLS(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	stream, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 3, 3),
		DstIP:   net.IPv4(10, 0, 3, 4),
		SrcPort: 50011,
		DstPort: 443,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	// Minimal TLS record + client hello marker for looksTLSClientHelloLite.
	tlsClientHello := []byte{0x16, 0x03, 0x03, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00}
	rep := stream.Feed(false, true, false, 0, tlsClientHello)
	if rep.Action != ActionBlock {
		t.Fatalf("action = %s, want block", rep.Action)
	}
	if rep.Traffic == nil || rep.Traffic.Label != "Web Service (HTTPS/TLS)" {
		t.Fatalf("traffic = %+v, want Web Service (HTTPS/TLS)", rep.Traffic)
	}
}

func TestTrafficPolicyDisableWebBlock(t *testing.T) {
	engine, err := NewEngine(DefaultConfig())
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	engine.SetTrafficPolicy(TrafficPolicy{
		Enabled:     false,
		BlockWebTCP: true,
	})
	stream, err := engine.NewTCPStream(StreamMeta{
		SrcIP:   net.IPv4(10, 0, 3, 5),
		DstIP:   net.IPv4(10, 0, 3, 6),
		SrcPort: 50012,
		DstPort: 80,
	})
	if err != nil {
		t.Fatalf("new tcp stream: %v", err)
	}
	rep := stream.Feed(false, true, false, 0, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	if rep.Action != ActionAllow {
		t.Fatalf("action = %s, want allow", rep.Action)
	}
	if rep.Reason != "no proxy signal" {
		t.Fatalf("reason = %s, want no proxy signal", rep.Reason)
	}
}
