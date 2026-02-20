package traffic

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/apernet/OpenGFW/analyzer"
)

func TestTCPClassifiesMinecraftJEServer(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 1),
		DstIP:   net.IPv4(10, 0, 0, 2),
		SrcPort: 50000,
		DstPort: 25565,
	}, nil)

	hs := buildMinecraftJEHandshake("mc.example.com", 25565, 760, 2)
	u, done := s.Feed(false, true, true, 0, hs)
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "MC Server (JE)" {
		t.Fatalf("label = %v, want MC Server (JE)", got)
	}
	if got := u.M["family"]; got != "minecraft" {
		t.Fatalf("family = %v, want minecraft", got)
	}
}

func TestTCPClassifiesMinecraftClientClient(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 3),
		DstIP:   net.IPv4(10, 0, 0, 4),
		SrcPort: 50001,
		DstPort: 40000,
	}, nil)

	hs := buildMinecraftJEHandshake("peer.local", 40000, 760, 1)
	u, done := s.Feed(false, true, true, 0, hs)
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "MC Client - Client" {
		t.Fatalf("label = %v, want MC Client - Client", got)
	}
}

func TestUDPClassifiesMinecraftBEServer(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewUDP(analyzer.UDPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 5),
		DstIP:   net.IPv4(10, 0, 0, 6),
		SrcPort: 50002,
		DstPort: 19132,
	}, nil)

	pkt := buildRakNetPing()
	u, done := s.Feed(false, pkt)
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "MC Server (BE)" {
		t.Fatalf("label = %v, want MC Server (BE)", got)
	}
}

func TestTCPClassifiesProxyTypeSocks5(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 7),
		DstIP:   net.IPv4(10, 0, 0, 8),
		SrcPort: 50003,
		DstPort: 1080,
	}, nil)

	u, done := s.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "Proxy (SOCKS5)" {
		t.Fatalf("label = %v, want Proxy (SOCKS5)", got)
	}
}

func TestTCPFallbackPortHeuristic(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 9),
		DstIP:   net.IPv4(10, 0, 0, 10),
		SrcPort: 50004,
		DstPort: 25565,
	}, nil)

	u, done := s.Feed(false, true, true, 0, []byte("NOT_MINECRAFT"))
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["method"]; got != "port_heuristic" {
		t.Fatalf("method = %v, want port_heuristic", got)
	}
	if got := u.M["label"]; got != "MC Server (JE)" {
		t.Fatalf("label = %v, want MC Server (JE)", got)
	}
}

func TestTCPFallbackUnknown(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 11),
		DstIP:   net.IPv4(10, 0, 0, 12),
		SrcPort: 50005,
		DstPort: 65000,
	}, nil)

	u, done := s.Feed(false, true, true, 0, []byte{0x13, 0x37, 0x42, 0x99})
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "Unknown Traffic" {
		t.Fatalf("label = %v, want Unknown Traffic", got)
	}
}

func TestTCPClassifiesWebHTTPBySignature(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 1, 1),
		DstIP:   net.IPv4(10, 0, 1, 2),
		SrcPort: 50100,
		DstPort: 50080,
	}, nil)

	u, done := s.Feed(false, true, false, 0, []byte("GET / HTTP/1.1\r\nHost: demo.local\r\n\r\n"))
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "Web Service (HTTP)" {
		t.Fatalf("label = %v, want Web Service (HTTP)", got)
	}
	if got := u.M["method"]; got != "tcp_signature" {
		t.Fatalf("method = %v, want tcp_signature", got)
	}
}

func TestUDPClassifiesDNSBySignature(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewUDP(analyzer.UDPInfo{
		SrcIP:   net.IPv4(10, 0, 1, 3),
		DstIP:   net.IPv4(10, 0, 1, 4),
		SrcPort: 50101,
		DstPort: 55000,
	}, nil)

	p := []byte{
		0xab, 0xcd, 0x01, 0x00, // id + flags
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	u, done := s.Feed(false, p)
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "DNS Service" {
		t.Fatalf("label = %v, want DNS Service", got)
	}
}

func TestTCPBuiltinPortTagRDP(t *testing.T) {
	ta := NewTrafficAnalyzer()
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 1, 5),
		DstIP:   net.IPv4(10, 0, 1, 6),
		SrcPort: 50102,
		DstPort: 3389,
	}, nil)

	u, done := s.Feed(false, true, true, 0, []byte{0x01, 0x02, 0x03})
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "Remote Desktop (RDP)" {
		t.Fatalf("label = %v, want Remote Desktop (RDP)", got)
	}
	if got := u.M["method"]; got != "builtin_port_tag" {
		t.Fatalf("method = %v, want builtin_port_tag", got)
	}
}

func TestCustomMinecraftJavaPortFromFeatureFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic-features.yaml")
	err := os.WriteFile(path, []byte("minecraft:\n  javaServerPorts: [40000]\n"), 0o600)
	if err != nil {
		t.Fatalf("write feature file: %v", err)
	}

	ta := NewTrafficAnalyzer()
	if err := ta.SetFeatureFile(path); err != nil {
		t.Fatalf("set feature file: %v", err)
	}
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 0, 13),
		DstIP:   net.IPv4(10, 0, 0, 14),
		SrcPort: 50006,
		DstPort: 40000,
	}, nil)

	hs := buildMinecraftJEHandshake("frp.local", 40000, 760, 2)
	u, done := s.Feed(false, true, true, 0, hs)
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "MC Server (JE)" {
		t.Fatalf("label = %v, want MC Server (JE)", got)
	}
}

func TestCustomServiceTagFromFeatureFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "traffic-features.yaml")
	cfg := "" +
		"serviceTags:\n" +
		"  - name: MSLFRP Node API\n" +
		"    family: mslfrp\n" +
		"    role: service\n" +
		"    transport: tcp\n" +
		"    ports: [25570]\n" +
		"    confidence: 93\n"
	err := os.WriteFile(path, []byte(cfg), 0o600)
	if err != nil {
		t.Fatalf("write feature file: %v", err)
	}

	ta := NewTrafficAnalyzer()
	if err := ta.SetFeatureFile(path); err != nil {
		t.Fatalf("set feature file: %v", err)
	}
	s := ta.NewTCP(analyzer.TCPInfo{
		SrcIP:   net.IPv4(10, 0, 1, 7),
		DstIP:   net.IPv4(10, 0, 1, 8),
		SrcPort: 50103,
		DstPort: 25570,
	}, nil)

	u, done := s.Feed(false, true, true, 0, []byte{0x12, 0x34})
	if u == nil || !done {
		t.Fatalf("expected update and done, got u=%v done=%v", u, done)
	}
	if got := u.M["label"]; got != "MSLFRP Node API" {
		t.Fatalf("label = %v, want MSLFRP Node API", got)
	}
	if got := u.M["method"]; got != "custom_port_tag" {
		t.Fatalf("method = %v, want custom_port_tag", got)
	}
}

func buildMinecraftJEHandshake(host string, port uint16, protocolVersion int, nextState int) []byte {
	payload := make([]byte, 0)
	payload = append(payload, encodeVarInt(0)...) // packet id
	payload = append(payload, encodeVarInt(protocolVersion)...)
	payload = append(payload, encodeVarInt(len(host))...)
	payload = append(payload, []byte(host)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	payload = append(payload, portBytes...)
	payload = append(payload, encodeVarInt(nextState)...)

	packet := make([]byte, 0, len(payload)+5)
	packet = append(packet, encodeVarInt(len(payload))...)
	packet = append(packet, payload...)
	return packet
}

func buildRakNetPing() []byte {
	p := []byte{0x01}
	p = append(p, make([]byte, 8)...)
	p = append(p, rakNetMagic...)
	p = append(p, make([]byte, 8)...)
	return p
}

func encodeVarInt(v int) []byte {
	out := make([]byte, 0, 5)
	uv := uint32(v)
	for {
		b := byte(uv & 0x7f)
		uv >>= 7
		if uv != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if uv == 0 {
			break
		}
	}
	return out
}
