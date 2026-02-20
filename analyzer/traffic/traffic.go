package traffic

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/proxy"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

var (
	_ analyzer.TCPAnalyzer = (*TrafficAnalyzer)(nil)
	_ analyzer.UDPAnalyzer = (*TrafficAnalyzer)(nil)
)

var rakNetMagic = []byte{
	0x00, 0xff, 0xff, 0x00, 0xfe, 0xfe, 0xfe, 0xfe,
	0xfd, 0xfd, 0xfd, 0xfd, 0x12, 0x34, 0x56, 0x78,
}

type builtinServiceTag struct {
	label      string
	family     string
	role       string
	transport  string // tcp / udp / any
	ports      []int
	confidence int
}

var builtinServiceTags = []builtinServiceTag{
	{label: "Web Service (HTTP)", family: "web", role: "server", transport: "tcp", ports: []int{80, 8080, 8000, 8888, 3000}, confidence: 72},
	{label: "Web Service (HTTPS/TLS)", family: "web", role: "server", transport: "tcp", ports: []int{443, 8443}, confidence: 74},
	{label: "Remote Admin (SSH)", family: "remote_admin", role: "server", transport: "tcp", ports: []int{22}, confidence: 80},
	{label: "Remote Desktop (RDP)", family: "remote_admin", role: "server", transport: "tcp", ports: []int{3389}, confidence: 80},
	{label: "DNS Service", family: "dns", role: "service", transport: "any", ports: []int{53}, confidence: 82},
	{label: "Database (MySQL)", family: "database", role: "server", transport: "tcp", ports: []int{3306}, confidence: 78},
	{label: "Database (PostgreSQL)", family: "database", role: "server", transport: "tcp", ports: []int{5432}, confidence: 78},
	{label: "Database (Redis)", family: "database", role: "server", transport: "tcp", ports: []int{6379}, confidence: 78},
	{label: "Database (MongoDB)", family: "database", role: "server", transport: "tcp", ports: []int{27017}, confidence: 78},
	{label: "Message Queue (MQTT)", family: "message_queue", role: "server", transport: "tcp", ports: []int{1883, 8883}, confidence: 78},
	{label: "NTP Service", family: "infrastructure", role: "service", transport: "udp", ports: []int{123}, confidence: 78},
	{label: "VPN Tunnel (OpenVPN)", family: "vpn", role: "service", transport: "any", ports: []int{1194}, confidence: 78},
	{label: "VPN Tunnel (WireGuard)", family: "vpn", role: "service", transport: "udp", ports: []int{51820}, confidence: 78},
}

func (a *TrafficAnalyzer) Name() string {
	return "traffic"
}

func (a *TrafficAnalyzer) Limit() int {
	return a.getFeatureConfig().TCPScanLimit
}

func (a *TrafficAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	cfg := a.getFeatureConfig()
	pa := proxy.NewProxyAnalyzer()
	return &tcpStream{
		reqBuf:       &utils.ByteBuffer{},
		cfg:          cfg,
		gray:         inGray(flowKeyTCP(info), cfg.GrayPercent),
		info:         info,
		proxyStream:  pa.NewTCP(info, nil),
		unknownScore: 20,
	}
}

func (a *TrafficAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	cfg := a.getFeatureConfig()
	pa := proxy.NewProxyAnalyzer()
	return &udpStream{
		cfg:          cfg,
		gray:         inGray(flowKeyUDP(info), cfg.GrayPercent),
		info:         info,
		proxyStream:  pa.NewUDP(info, nil),
		unknownScore: 20,
	}
}

type tcpStream struct {
	reqBuf *utils.ByteBuffer

	cfg  FeatureConfig
	gray bool
	info analyzer.TCPInfo

	proxyStream analyzer.TCPStream

	done         bool
	unknownScore int
}

func (s *tcpStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if s.done {
		return nil, true
	}
	if skip != 0 {
		s.done = true
		return s.update(s.fallbackClassification()), true
	}
	if len(data) == 0 {
		if end {
			s.done = true
			return s.update(s.fallbackClassification()), true
		}
		return nil, false
	}

	if !rev {
		s.reqBuf.Append(data)
		if m, ok, _ := parseMinecraftJavaHandshake(s.reqBuf.Buf, s.info, s.cfg); ok {
			s.done = true
			return s.update(m), true
		}
	}

	if s.proxyStream != nil {
		pu, pdone := s.proxyStream.Feed(rev, start, end, skip, data)
		if pu != nil && pu.M != nil {
			if m := mapProxyClassification(pu.M, "tcp"); m != nil {
				s.done = true
				return s.update(m), true
			}
		}
		if pdone {
			s.proxyStream = nil
		}
	}

	if !rev {
		if m, ok := classifyTCPBySignature(s.reqBuf.Buf, s.info); ok {
			s.done = true
			return s.update(m), true
		}
	}

	if len(s.reqBuf.Buf) >= s.cfg.TCPScanLimit || end {
		s.done = true
		return s.update(s.fallbackClassification()), true
	}
	return nil, false
}

func (s *tcpStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	if s.done {
		return nil
	}
	s.done = true
	return s.update(s.fallbackClassification())
}

func (s *tcpStream) fallbackClassification() analyzer.PropMap {
	if hasPort(s.info.SrcPort, s.cfg.Minecraft.JavaServerPorts) || hasPort(s.info.DstPort, s.cfg.Minecraft.JavaServerPorts) {
		return buildMinecraftClassification("MC Server (JE)", "server", "java", "tcp", "port_heuristic", 55, analyzer.PropMap{
			"likely_server_port": likelyMinecraftPort(s.info, s.cfg.Minecraft.JavaServerPorts),
		})
	}
	if m, ok := classifyTCPByCustomPortTag(s.info, s.cfg); ok {
		return m
	}
	if m, ok := classifyTCPByBuiltinPortTag(s.info, s.cfg); ok {
		return m
	}
	return unknownClassification("tcp", s.unknownScore)
}

func (s *tcpStream) update(m analyzer.PropMap) *analyzer.PropUpdate {
	if !s.gray {
		return nil
	}
	return replaceUpdate(m)
}

type udpStream struct {
	cfg  FeatureConfig
	gray bool
	info analyzer.UDPInfo

	proxyStream analyzer.UDPStream
	done        bool

	invalidCount int
	unknownScore int
}

func (s *udpStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if s.done {
		return nil, true
	}
	if len(data) == 0 {
		return nil, false
	}

	if m, ok := parseMinecraftBedrockPacket(data, s.info, s.cfg); ok {
		s.done = true
		return s.update(m), true
	}

	if s.proxyStream != nil {
		pu, pdone := s.proxyStream.Feed(rev, data)
		if pu != nil && pu.M != nil {
			if m := mapProxyClassification(pu.M, "udp"); m != nil {
				s.done = true
				return s.update(m), true
			}
		}
		if pdone {
			s.proxyStream = nil
		}
	}

	if m, ok := classifyUDPBySignature(data, s.info); ok {
		s.done = true
		return s.update(m), true
	}

	s.invalidCount++
	if s.invalidCount >= s.cfg.UDPInvalidCountThreshold {
		s.done = true
		return s.update(s.fallbackClassification()), true
	}
	return nil, false
}

func (s *udpStream) Close(limited bool) *analyzer.PropUpdate {
	if s.done {
		return nil
	}
	s.done = true
	return s.update(s.fallbackClassification())
}

func (s *udpStream) fallbackClassification() analyzer.PropMap {
	if hasPort(s.info.SrcPort, s.cfg.Minecraft.BedrockServerPorts) || hasPort(s.info.DstPort, s.cfg.Minecraft.BedrockServerPorts) {
		return buildMinecraftClassification("MC Server (BE)", "server", "bedrock", "udp", "port_heuristic", 55, analyzer.PropMap{
			"likely_server_port": likelyMinecraftPortUDP(s.info, s.cfg.Minecraft.BedrockServerPorts),
		})
	}
	if m, ok := classifyUDPByCustomPortTag(s.info, s.cfg); ok {
		return m
	}
	if m, ok := classifyUDPByBuiltinPortTag(s.info, s.cfg); ok {
		return m
	}
	return unknownClassification("udp", s.unknownScore)
}

func (s *udpStream) update(m analyzer.PropMap) *analyzer.PropUpdate {
	if !s.gray {
		return nil
	}
	return replaceUpdate(m)
}

func parseMinecraftJavaHandshake(bs []byte, info analyzer.TCPInfo, cfg FeatureConfig) (m analyzer.PropMap, ok bool, pending bool) {
	packetLen, pos, ok, pending := readVarInt(bs, 0)
	if pending {
		return nil, false, true
	}
	if !ok || packetLen <= 0 || packetLen > 2048 {
		return nil, false, false
	}
	if len(bs) < pos+packetLen {
		return nil, false, true
	}
	packetEnd := pos + packetLen

	packetID, pos, ok, pending := readVarInt(bs, pos)
	if pending {
		return nil, false, true
	}
	if !ok || packetID != 0 {
		return nil, false, false
	}

	protoVersion, pos, ok, pending := readVarInt(bs, pos)
	if pending {
		return nil, false, true
	}
	if !ok {
		return nil, false, false
	}

	hostLen, pos, ok, pending := readVarInt(bs, pos)
	if pending {
		return nil, false, true
	}
	if !ok || hostLen <= 0 || hostLen > 255 {
		return nil, false, false
	}
	if pos+hostLen+2 > len(bs) {
		return nil, false, true
	}
	if pos+hostLen+2 > packetEnd {
		return nil, false, false
	}
	host := string(bs[pos : pos+hostLen])
	pos += hostLen

	serverPort := int(binary.BigEndian.Uint16(bs[pos : pos+2]))
	pos += 2

	nextState, pos, ok, pending := readVarInt(bs, pos)
	if pending {
		return nil, false, true
	}
	if !ok || pos > packetEnd {
		return nil, false, false
	}

	label, role, confidence := classifyJavaRole(info, uint16(serverPort), cfg)
	return buildMinecraftClassification(label, role, "java", "tcp", "minecraft_java_handshake", confidence, analyzer.PropMap{
		"protocol_version": protoVersion,
		"host":             host,
		"server_port":      serverPort,
		"next_state":       nextState,
	}), true, false
}

func parseMinecraftBedrockPacket(data []byte, info analyzer.UDPInfo, cfg FeatureConfig) (analyzer.PropMap, bool) {
	if len(data) < 1 {
		return nil, false
	}
	packetID := data[0]
	if !isRakNetPacketID(packetID) {
		return nil, false
	}
	if bytes.Index(data, rakNetMagic) < 0 {
		return nil, false
	}
	label, role, confidence := classifyBedrockRole(info, cfg)
	return buildMinecraftClassification(label, role, "bedrock", "udp", "raknet_magic", confidence, analyzer.PropMap{
		"packet_id":   int(packetID),
		"packet_name": rakNetPacketName(packetID),
	}), true
}

func buildMinecraftClassification(label, role, edition, transport, method string, confidence int, extra analyzer.PropMap) analyzer.PropMap {
	mc := analyzer.PropMap{
		"edition": edition,
	}
	for k, v := range extra {
		mc[k] = v
	}
	return analyzer.PropMap{
		"family":     "minecraft",
		"label":      label,
		"role":       role,
		"transport":  transport,
		"method":     method,
		"confidence": clampScore(confidence),
		"minecraft":  mc,
	}
}

func classifyJavaRole(info analyzer.TCPInfo, handshakePort uint16, cfg FeatureConfig) (label, role string, confidence int) {
	if hasPort(info.DstPort, cfg.Minecraft.JavaServerPorts) ||
		hasPort(info.SrcPort, cfg.Minecraft.JavaServerPorts) ||
		hasPort(handshakePort, cfg.Minecraft.JavaServerPorts) {
		return "MC Server (JE)", "server", 96
	}
	return "MC Client - Client", "client_client", 82
}

func classifyBedrockRole(info analyzer.UDPInfo, cfg FeatureConfig) (label, role string, confidence int) {
	if hasPort(info.DstPort, cfg.Minecraft.BedrockServerPorts) ||
		hasPort(info.SrcPort, cfg.Minecraft.BedrockServerPorts) {
		return "MC Server (BE)", "server", 95
	}
	return "MC Client - Client", "client_client", 82
}

func mapProxyClassification(pm analyzer.PropMap, transport string) analyzer.PropMap {
	protocol, _ := pm["protocol"].(string)
	if protocol == "" {
		return nil
	}
	score, ok := toInt(pm["sensitivity_score"])
	if !ok || score <= 0 {
		score = 75
	}

	family := "proxy"
	role := "proxy_path"
	label := fmt.Sprintf("Proxy (%s)", protocol)
	switch protocol {
	case "socks5", "socks5_udp_relay":
		label = "Proxy (SOCKS5)"
	case "socks4", "socks4a":
		label = "Proxy (SOCKS4/4A)"
	case "http_connect":
		label = "Proxy (HTTP CONNECT)"
	case "trojan_like":
		label = "Proxy (Trojan-like)"
	case "v2ray_family_like":
		label = "Proxy (VMess/VLESS-like)"
	case "hysteria2":
		label = "Proxy (Hysteria2)"
	case "tuic":
		label = "Proxy (TUIC)"
	case "shadowsocks_vmess_like", "shadowsocks_vmess_like_udp":
		label = "Proxy (SS/VMess/VLESS-like)"
	case "tls_proxy_tunnel_like":
		label = "Proxy (TLS Tunnel-like)"
	case "quic_tunnel_candidate":
		label = "Proxy Candidate (QUIC Tunnel)"
		role = "candidate"
	case "openvpn_tcp", "openvpn_udp":
		family = "vpn"
		label = "VPN Tunnel (OpenVPN)"
	case "wireguard":
		family = "vpn"
		label = "VPN Tunnel (WireGuard)"
	case "ssh_tunnel":
		family = "encrypted_tunnel"
		label = "Encrypted Tunnel (SSH)"
		role = "candidate"
	case "source_ip_penalty":
		family = "enforcement"
		label = "Proxy Source Penalty"
		role = "blocked_source"
	}

	out := analyzer.PropMap{
		"family":     family,
		"label":      label,
		"role":       role,
		"transport":  transport,
		"method":     "proxy_fingerprint",
		"confidence": clampScore(score),
		"proxy": analyzer.PropMap{
			"protocol":          protocol,
			"type":              pm["type"],
			"class":             pm["class"],
			"sensitivity_score": pm["sensitivity_score"],
			"sensitivity_level": pm["sensitivity_level"],
		},
	}
	if sig, ok := pm["signals"]; ok {
		out["signals"] = sig
	}
	return out
}

func classifyTCPBySignature(bs []byte, info analyzer.TCPInfo) (analyzer.PropMap, bool) {
	if len(bs) == 0 {
		return nil, false
	}
	if looksHTTPRequest(bs) {
		return serviceClassification("Web Service (HTTP)", "web", "server", "tcp", "tcp_signature", 86, analyzer.PropMap{
			"signature": "http_request_line",
		}), true
	}
	if looksTLSClientHelloLite(bs) {
		return serviceClassification("Web Service (HTTPS/TLS)", "web", "server", "tcp", "tcp_signature", 84, analyzer.PropMap{
			"signature": "tls_client_hello",
		}), true
	}
	if looksSSHBanner(bs) {
		return serviceClassification("Remote Admin (SSH)", "remote_admin", "server", "tcp", "tcp_signature", 90, analyzer.PropMap{
			"signature": "ssh_banner",
		}), true
	}
	if looksRDPX224(bs) {
		return serviceClassification("Remote Desktop (RDP)", "remote_admin", "server", "tcp", "tcp_signature", 88, analyzer.PropMap{
			"signature": "rdp_x224_tpkt",
		}), true
	}
	if looksPostgreSQLStartup(bs) {
		return serviceClassification("Database (PostgreSQL)", "database", "server", "tcp", "tcp_signature", 88, analyzer.PropMap{
			"signature": "postgres_startup",
		}), true
	}
	if looksRedisRESP(bs) {
		return serviceClassification("Database (Redis)", "database", "server", "tcp", "tcp_signature", 84, analyzer.PropMap{
			"signature": "redis_resp",
		}), true
	}
	if looksMQTTConnect(bs) {
		return serviceClassification("Message Queue (MQTT)", "message_queue", "server", "tcp", "tcp_signature", 84, analyzer.PropMap{
			"signature": "mqtt_connect",
		}), true
	}
	_ = info
	return nil, false
}

func classifyUDPBySignature(data []byte, info analyzer.UDPInfo) (analyzer.PropMap, bool) {
	if len(data) == 0 {
		return nil, false
	}
	if looksDNSPacketLite(data) {
		return serviceClassification("DNS Service", "dns", "service", "udp", "udp_signature", 88, analyzer.PropMap{
			"signature": "dns_header",
		}), true
	}
	if looksQUICLongHeaderLite(data) {
		return serviceClassification("QUIC Transport", "quic", "service", "udp", "udp_signature", 80, analyzer.PropMap{
			"signature": "quic_long_header",
		}), true
	}
	if looksSTUN(data) {
		return serviceClassification("VoIP/Traversal (STUN)", "nat_traversal", "service", "udp", "udp_signature", 80, analyzer.PropMap{
			"signature": "stun_magic_cookie",
		}), true
	}
	_ = info
	return nil, false
}

func classifyTCPByCustomPortTag(info analyzer.TCPInfo, cfg FeatureConfig) (analyzer.PropMap, bool) {
	for _, tag := range cfg.ServiceTags {
		if tag.Transport != "any" && tag.Transport != "tcp" {
			continue
		}
		port := matchedPort(info.SrcPort, info.DstPort, tag.Ports)
		if port == 0 {
			continue
		}
		return serviceClassification(tag.Name, tag.Family, tag.Role, "tcp", "custom_port_tag", tag.Confidence, analyzer.PropMap{
			"port": port,
		}), true
	}
	return nil, false
}

func classifyUDPByCustomPortTag(info analyzer.UDPInfo, cfg FeatureConfig) (analyzer.PropMap, bool) {
	for _, tag := range cfg.ServiceTags {
		if tag.Transport != "any" && tag.Transport != "udp" {
			continue
		}
		port := matchedPort(info.SrcPort, info.DstPort, tag.Ports)
		if port == 0 {
			continue
		}
		return serviceClassification(tag.Name, tag.Family, tag.Role, "udp", "custom_port_tag", tag.Confidence, analyzer.PropMap{
			"port": port,
		}), true
	}
	return nil, false
}

func classifyTCPByBuiltinPortTag(info analyzer.TCPInfo, cfg FeatureConfig) (analyzer.PropMap, bool) {
	if !cfg.BuiltinPortTagEnabled {
		return nil, false
	}
	for _, tag := range builtinServiceTags {
		if tag.transport != "any" && tag.transport != "tcp" {
			continue
		}
		port := matchedPort(info.SrcPort, info.DstPort, tag.ports)
		if port == 0 {
			continue
		}
		return serviceClassification(tag.label, tag.family, tag.role, "tcp", "builtin_port_tag", tag.confidence, analyzer.PropMap{
			"port": port,
		}), true
	}
	return nil, false
}

func classifyUDPByBuiltinPortTag(info analyzer.UDPInfo, cfg FeatureConfig) (analyzer.PropMap, bool) {
	if !cfg.BuiltinPortTagEnabled {
		return nil, false
	}
	for _, tag := range builtinServiceTags {
		if tag.transport != "any" && tag.transport != "udp" {
			continue
		}
		port := matchedPort(info.SrcPort, info.DstPort, tag.ports)
		if port == 0 {
			continue
		}
		return serviceClassification(tag.label, tag.family, tag.role, "udp", "builtin_port_tag", tag.confidence, analyzer.PropMap{
			"port": port,
		}), true
	}
	return nil, false
}

func serviceClassification(label, family, role, transport, method string, confidence int, details analyzer.PropMap) analyzer.PropMap {
	m := analyzer.PropMap{
		"family":     family,
		"label":      label,
		"role":       role,
		"transport":  transport,
		"method":     method,
		"confidence": clampScore(confidence),
	}
	if len(details) > 0 {
		m["service"] = details
	}
	return m
}

func unknownClassification(transport string, confidence int) analyzer.PropMap {
	return analyzer.PropMap{
		"family":     "unknown",
		"label":      "Unknown Traffic",
		"role":       "unknown",
		"transport":  transport,
		"method":     "fallback",
		"confidence": clampScore(confidence),
	}
}

func looksHTTPRequest(bs []byte) bool {
	if len(bs) < 8 {
		return false
	}
	sample := bs
	if len(sample) > 96 {
		sample = sample[:96]
	}
	lineEnd := bytes.Index(sample, []byte("\r\n"))
	if lineEnd < 0 {
		return false
	}
	line := string(sample[:lineEnd])
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT "}
	okMethod := false
	for _, m := range methods {
		if strings.HasPrefix(line, m) {
			okMethod = true
			break
		}
	}
	if !okMethod {
		return false
	}
	return strings.Contains(line, " HTTP/")
}

func looksTLSClientHelloLite(bs []byte) bool {
	if len(bs) < 9 {
		return false
	}
	if bs[0] != 0x16 || bs[1] != 0x03 {
		return false
	}
	recLen := int(binary.BigEndian.Uint16(bs[3:5]))
	if recLen < 4 || recLen > 16384 {
		return false
	}
	if 5+recLen > len(bs) {
		return false
	}
	return bs[5] == 0x01
}

func looksSSHBanner(bs []byte) bool {
	if len(bs) < 7 {
		return false
	}
	return bytes.HasPrefix(bs, []byte("SSH-"))
}

func looksRDPX224(bs []byte) bool {
	if len(bs) < 7 {
		return false
	}
	if bs[0] != 0x03 || bs[1] != 0x00 {
		return false
	}
	tpktLen := int(binary.BigEndian.Uint16(bs[2:4]))
	if tpktLen < 7 || tpktLen > 4096 || tpktLen > len(bs) {
		return false
	}
	// X.224 class 0 connection request/confirm
	return bs[5] == 0xe0 || bs[5] == 0xd0
}

func looksPostgreSQLStartup(bs []byte) bool {
	if len(bs) < 8 {
		return false
	}
	totalLen := int(binary.BigEndian.Uint32(bs[:4]))
	if totalLen < 8 || totalLen > 4096 || totalLen > len(bs) {
		return false
	}
	ver := binary.BigEndian.Uint32(bs[4:8])
	return ver == 0x00030000
}

func looksRedisRESP(bs []byte) bool {
	if len(bs) < 4 {
		return false
	}
	switch bs[0] {
	case '*', '+', '-', ':', '$':
	default:
		return false
	}
	return bytes.Contains(bs[:minInt(len(bs), 64)], []byte("\r\n"))
}

func looksMQTTConnect(bs []byte) bool {
	if len(bs) < 10 {
		return false
	}
	if bs[0] != 0x10 {
		return false
	}
	return bytes.Contains(bs[:minInt(len(bs), 64)], []byte("MQTT"))
}

func looksDNSPacketLite(bs []byte) bool {
	if len(bs) < 12 {
		return false
	}
	qd := int(binary.BigEndian.Uint16(bs[4:6]))
	an := int(binary.BigEndian.Uint16(bs[6:8]))
	ns := int(binary.BigEndian.Uint16(bs[8:10]))
	ar := int(binary.BigEndian.Uint16(bs[10:12]))
	total := qd + an + ns + ar
	if total <= 0 || total > 64 {
		return false
	}
	opcode := (bs[2] >> 3) & 0x0f
	return opcode <= 5
}

func looksQUICLongHeaderLite(bs []byte) bool {
	if len(bs) < 6 {
		return false
	}
	if bs[0]&0x80 == 0 {
		return false
	}
	ver := binary.BigEndian.Uint32(bs[1:5])
	return ver != 0
}

func looksSTUN(bs []byte) bool {
	if len(bs) < 20 {
		return false
	}
	// STUN first 2 bits are zero.
	if bs[0]&0xc0 != 0 {
		return false
	}
	cookie := binary.BigEndian.Uint32(bs[4:8])
	return cookie == 0x2112A442
}

func readVarInt(bs []byte, offset int) (value int, next int, ok bool, pending bool) {
	if offset >= len(bs) {
		return 0, offset, false, true
	}
	for i := 0; i < 5; i++ {
		idx := offset + i
		if idx >= len(bs) {
			return 0, offset, false, true
		}
		b := bs[idx]
		value |= int(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return value, idx + 1, true, false
		}
	}
	return 0, offset, false, false
}

func isRakNetPacketID(id byte) bool {
	switch id {
	case 0x01, 0x1c, 0x05, 0x06, 0x07, 0x08:
		return true
	default:
		return false
	}
}

func rakNetPacketName(id byte) string {
	switch id {
	case 0x01:
		return "unconnected_ping"
	case 0x1c:
		return "unconnected_pong"
	case 0x05:
		return "open_connection_request_1"
	case 0x06:
		return "open_connection_reply_1"
	case 0x07:
		return "open_connection_request_2"
	case 0x08:
		return "open_connection_reply_2"
	default:
		return "unknown"
	}
}

func hasPort(port uint16, ports []int) bool {
	for _, p := range ports {
		if p == int(port) {
			return true
		}
	}
	return false
}

func matchedPort(srcPort, dstPort uint16, ports []int) int {
	if hasPort(dstPort, ports) {
		return int(dstPort)
	}
	if hasPort(srcPort, ports) {
		return int(srcPort)
	}
	return 0
}

func likelyMinecraftPort(info analyzer.TCPInfo, ports []int) int {
	if hasPort(info.DstPort, ports) {
		return int(info.DstPort)
	}
	if hasPort(info.SrcPort, ports) {
		return int(info.SrcPort)
	}
	return 0
}

func likelyMinecraftPortUDP(info analyzer.UDPInfo, ports []int) int {
	if hasPort(info.DstPort, ports) {
		return int(info.DstPort)
	}
	if hasPort(info.SrcPort, ports) {
		return int(info.SrcPort)
	}
	return 0
}

func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

func replaceUpdate(m analyzer.PropMap) *analyzer.PropUpdate {
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M:    m,
	}
}

func toInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case uint64:
		return int(x), true
	case float64:
		return int(x), true
	default:
		return 0, false
	}
}

func flowKeyTCP(info analyzer.TCPInfo) string {
	return info.SrcIP.String() + ":" + strconv.Itoa(int(info.SrcPort)) + "->" +
		info.DstIP.String() + ":" + strconv.Itoa(int(info.DstPort))
}

func flowKeyUDP(info analyzer.UDPInfo) string {
	return info.SrcIP.String() + ":" + strconv.Itoa(int(info.SrcPort)) + "->" +
		info.DstIP.String() + ":" + strconv.Itoa(int(info.DstPort))
}

func inGray(key string, percent int) bool {
	if percent >= 100 {
		return true
	}
	if percent <= 0 {
		return false
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return int(h.Sum32()%100) < percent
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
