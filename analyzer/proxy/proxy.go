package proxy

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/internal"
	"github.com/apernet/OpenGFW/analyzer/utils"
)

const (
	proxyTCPScanLimit          = 4096
	proxyTCPEncryptedMinBytes  = 96
	proxyTCPEntropyThreshold   = 6.8
	proxyTCPPrintableThreshold = 0.50

	proxyUDPInvalidCountThreshold = 10
	proxyUDPEncryptedMinBytes     = 96
	proxyUDPEntropyThreshold      = 6.8
	proxyUDPPrintableThreshold    = 0.45
)

const (
	openVPNMinPktLen = 6
	openVPNMaxPktLen = 8192
)

const (
	openVPNControlHardResetClientV1 = 1
	openVPNControlHardResetServerV1 = 2
	openVPNControlSoftResetV1       = 3
	openVPNControlV1                = 4
	openVPNAckV1                    = 5
	openVPNDataV1                   = 6
	openVPNControlHardResetClientV2 = 7
	openVPNControlHardResetServerV2 = 8
	openVPNDataV2                   = 9
	openVPNControlHardResetClientV3 = 10
	openVPNControlWkcV1             = 11
)

const (
	wireGuardTypeHandshakeInitiation = 1
	wireGuardTypeHandshakeResponse   = 2
	wireGuardTypeData                = 4
	wireGuardTypeCookieReply         = 3
)

const (
	wireGuardSizeHandshakeInitiation = 148
	wireGuardSizeHandshakeResponse   = 92
	wireGuardMinSizePacketData       = 32
	wireGuardSizePacketCookieReply   = 64
)

var (
	_ analyzer.TCPAnalyzer = (*ProxyAnalyzer)(nil)
	_ analyzer.UDPAnalyzer = (*ProxyAnalyzer)(nil)
)

// ProxyAnalyzer provides sensitive monitoring signals for proxy-related traffic.
// It uses explicit protocol fingerprints first, then encrypted-tunnel heuristics.
type ProxyAnalyzer struct {
	mu          sync.RWMutex
	cfg         FeatureConfig
	featureFile string
	penalty     *sourcePenaltyCache
}

func (a *ProxyAnalyzer) Name() string {
	return "proxy"
}

func (a *ProxyAnalyzer) Limit() int {
	return proxyTCPScanLimit
}

func (a *ProxyAnalyzer) NewTCP(info analyzer.TCPInfo, logger analyzer.Logger) analyzer.TCPStream {
	cfg := a.getFeatureConfig()
	return &tcpStream{
		reqBuf: &utils.ByteBuffer{},
		cfg:    cfg,
		gray:   inGray(flowKeyTCP(info), cfg.GrayPercent),
		srcIP:  append(net.IP(nil), info.SrcIP...),
		pen:    a.penalty,
	}
}

func (a *ProxyAnalyzer) NewUDP(info analyzer.UDPInfo, logger analyzer.Logger) analyzer.UDPStream {
	cfg := a.getFeatureConfig()
	return &udpStream{
		cfg:   cfg,
		gray:  inGray(flowKeyUDP(info), cfg.GrayPercent),
		srcIP: append(net.IP(nil), info.SrcIP...),
		pen:   a.penalty,
	}
}

type tcpStream struct {
	reqBuf *utils.ByteBuffer
	cfg    FeatureConfig
	gray   bool
	srcIP  net.IP
	pen    *sourcePenaltyCache
	done   bool
}

func (s *tcpStream) Feed(rev, start, end bool, skip int, data []byte) (u *analyzer.PropUpdate, done bool) {
	if s.done {
		return nil, true
	}
	if skip != 0 {
		s.done = true
		return nil, true
	}
	if len(data) == 0 {
		if end {
			s.done = true
			return nil, true
		}
		return nil, false
	}

	// Most proxy handshakes that can be fingerprinted appear client->server first.
	if rev {
		return nil, false
	}
	if m, ok := s.sourcePenaltyUpdate(); ok {
		s.done = true
		return s.update(m), true
	}

	s.reqBuf.Append(data)
	bs := s.reqBuf.Buf
	if m, ok := parseSocks5Request(bs); ok {
		s.done = true
		return s.update(m), true
	}
	if m, ok, pending := parseSocks4Request(bs); ok {
		s.done = true
		return s.update(m), true
	} else if pending {
		return nil, false
	}
	if m, ok, pending := parseHTTPConnectRequest(bs); ok {
		s.done = true
		return s.update(m), true
	} else if pending {
		return nil, false
	}
	if m, ok, pending := parseOpenVPNTCP(bs); ok {
		s.done = true
		return s.update(m), true
	} else if pending {
		return nil, false
	}
	if m, ok, pending := parseTLSProxyFingerprint(bs, s.cfg); ok {
		s.done = true
		return s.update(m), true
	} else if pending {
		return nil, false
	}
	if m, ok, pending := parseSSHHandshake(bs); ok {
		s.done = true
		return s.update(m), true
	} else if pending {
		return nil, false
	}
	if len(bs) >= s.cfg.TCPEncryptedMinBytes {
		if m, ok := detectEncryptedProxyTCP(bs, s.cfg); ok {
			s.done = true
			return s.update(m), true
		}
	}
	if len(bs) >= proxyTCPScanLimit || end {
		s.done = true
		return nil, true
	}
	return nil, false
}

func (s *tcpStream) Close(limited bool) *analyzer.PropUpdate {
	s.reqBuf.Reset()
	return nil
}

func (s *tcpStream) update(m analyzer.PropMap) *analyzer.PropUpdate {
	s.penalizeIfNeeded(m)
	if p, ok := m["protocol"].(string); ok && p == "source_ip_penalty" {
		return replaceUpdate(m)
	}
	if !s.gray {
		return nil
	}
	return replaceUpdate(m)
}

type udpStream struct {
	invalidCount int
	cfg          FeatureConfig
	gray         bool
	srcIP        net.IP
	pen          *sourcePenaltyCache
}

func (s *udpStream) Feed(rev bool, data []byte) (u *analyzer.PropUpdate, done bool) {
	if len(data) == 0 {
		return nil, false
	}
	if m, ok := s.sourcePenaltyUpdate(); ok {
		return s.update(m), true
	}
	if m, ok := parseSocks5UDPRelay(data); ok {
		s.invalidCount = 0
		return s.update(m), false
	}
	if m, ok := parseWireGuard(data); ok {
		s.invalidCount = 0
		return s.update(m), false
	}
	if m, ok := parseOpenVPNUDP(data); ok {
		s.invalidCount = 0
		return s.update(m), false
	}
	if m, ok := parseQUICInitialLite(data); ok {
		s.invalidCount = 0
		return s.update(m), false
	}
	if m, ok := detectEncryptedProxyUDP(data, s.cfg); ok {
		s.invalidCount = 0
		return s.update(m), false
	}
	s.invalidCount++
	return nil, s.invalidCount >= s.cfg.UDPInvalidCountThreshold
}

func (s *udpStream) Close(limited bool) *analyzer.PropUpdate {
	return nil
}

func (s *udpStream) update(m analyzer.PropMap) *analyzer.PropUpdate {
	s.penalizeIfNeeded(m)
	if p, ok := m["protocol"].(string); ok && p == "source_ip_penalty" {
		return replaceUpdate(m)
	}
	if !s.gray {
		return nil
	}
	return replaceUpdate(m)
}

func (s *tcpStream) penalizeIfNeeded(m analyzer.PropMap) {
	if s.pen == nil || s.srcIP == nil {
		return
	}
	score, ok := toInt(m["sensitivity_score"])
	if !ok {
		return
	}
	s.pen.MaybePenalize(s.srcIP, score)
}

func (s *udpStream) penalizeIfNeeded(m analyzer.PropMap) {
	if s.pen == nil || s.srcIP == nil {
		return
	}
	score, ok := toInt(m["sensitivity_score"])
	if !ok {
		return
	}
	s.pen.MaybePenalize(s.srcIP, score)
}

func (s *tcpStream) sourcePenaltyUpdate() (analyzer.PropMap, bool) {
	if s.pen == nil || s.srcIP == nil {
		return nil, false
	}
	blocked, ttlSec, blockScore := s.pen.IsBlocked(s.srcIP)
	if !blocked {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":     "source_penalty",
		"class":    "enforcement",
		"protocol": "source_ip_penalty",
		"source_penalty": analyzer.PropMap{
			"active":            true,
			"ttl_remaining_sec": ttlSec,
		},
	}, blockScore, []string{"source-ip-penalty-cache"}), true
}

func (s *udpStream) sourcePenaltyUpdate() (analyzer.PropMap, bool) {
	if s.pen == nil || s.srcIP == nil {
		return nil, false
	}
	blocked, ttlSec, blockScore := s.pen.IsBlocked(s.srcIP)
	if !blocked {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":     "source_penalty",
		"class":    "enforcement",
		"protocol": "source_ip_penalty",
		"source_penalty": analyzer.PropMap{
			"active":            true,
			"ttl_remaining_sec": ttlSec,
		},
	}, blockScore, []string{"source-ip-penalty-cache"}), true
}

func replaceUpdate(m analyzer.PropMap) *analyzer.PropUpdate {
	return &analyzer.PropUpdate{
		Type: analyzer.PropUpdateReplace,
		M:    m,
	}
}

func parseSocks5Request(bs []byte) (analyzer.PropMap, bool) {
	if len(bs) < 2 || bs[0] != 0x05 {
		return nil, false
	}
	methodCount := int(bs[1])
	if methodCount <= 0 || methodCount > 16 {
		return nil, false
	}
	if len(bs) < 2+methodCount {
		return nil, false
	}
	methods := make([]int, methodCount)
	for i := range methods {
		methods[i] = int(bs[2+i])
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":                       "explicit_proxy",
		"class":                      "proxy",
		"protocol":                   "socks5",
		"auth_methods":               methods,
		"client_software_candidates": []string{"clash", "sing-box", "xray"},
	}, 98, []string{"socks5-client-greeting"}), true
}

func parseSocks4Request(bs []byte) (m analyzer.PropMap, ok bool, pending bool) {
	if len(bs) == 0 || bs[0] != 0x04 {
		return nil, false, false
	}
	if len(bs) < 9 {
		return nil, false, true
	}
	cmd := bs[1]
	if cmd != 0x01 && cmd != 0x02 {
		return nil, false, false
	}
	userEnd := bytes.IndexByte(bs[8:], 0x00)
	if userEnd < 0 {
		return nil, false, true
	}
	userID := string(bs[8 : 8+userEnd])
	dstPort := int(binary.BigEndian.Uint16(bs[2:4]))
	is4A := bs[4] == 0x00 && bs[5] == 0x00 && bs[6] == 0x00 && bs[7] != 0x00

	protocol := "socks4"
	addrType := "ipv4"
	addr := net.IPv4(bs[4], bs[5], bs[6], bs[7]).String()
	next := 8 + userEnd + 1
	if is4A {
		hostEnd := bytes.IndexByte(bs[next:], 0x00)
		if hostEnd < 0 {
			return nil, false, true
		}
		if hostEnd == 0 {
			return nil, false, false
		}
		protocol = "socks4a"
		addrType = "domain"
		addr = string(bs[next : next+hostEnd])
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":                       "explicit_proxy",
		"class":                      "proxy",
		"protocol":                   protocol,
		"cmd":                        int(cmd),
		"addr_type":                  addrType,
		"addr":                       addr,
		"port":                       dstPort,
		"user_id":                    userID,
		"client_software_candidates": []string{"clash", "sing-box", "xray"},
	}, 97, []string{"socks4-request"}), true, false
}

func parseHTTPConnectRequest(bs []byte) (m analyzer.PropMap, ok bool, pending bool) {
	if len(bs) == 0 {
		return nil, false, false
	}
	lineEnd := bytes.Index(bs, []byte("\r\n"))
	if lineEnd < 0 {
		n := minInt(len(bs), len("CONNECT "))
		if strings.HasPrefix("CONNECT ", strings.ToUpper(string(bs[:n]))) {
			return nil, false, true
		}
		return nil, false, false
	}
	line := string(bs[:lineEnd])
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.EqualFold(fields[0], "CONNECT") {
		return nil, false, false
	}
	target := fields[1]
	resp := analyzer.PropMap{
		"type":                       "explicit_proxy",
		"class":                      "proxy",
		"protocol":                   "http_connect",
		"target":                     target,
		"client_software_candidates": []string{"clash", "sing-box", "xray"},
	}
	if host, port, hasPort := splitHostPortLoose(target); hasPort {
		resp["target_host"] = host
		resp["target_port"] = port
	}
	return annotateSensitivity(resp, 96, []string{"http-connect-request"}), true, false
}

func parseSocks5UDPRelay(data []byte) (analyzer.PropMap, bool) {
	// +----+----+----+----+------+----------+----------+
	// |RSV |RSV |FRAG|ATYP|DST.ADDR|DST.PORT|   DATA   |
	// +----+----+----+----+------+----------+----------+
	if len(data) < 10 || data[0] != 0 || data[1] != 0 || data[2] != 0 {
		return nil, false
	}
	atyp := data[3]
	i := 4
	addrType := ""
	addr := ""
	switch atyp {
	case 0x01:
		if len(data) < i+4+2 {
			return nil, false
		}
		addrType = "ipv4"
		addr = net.IPv4(data[i], data[i+1], data[i+2], data[i+3]).String()
		i += 4
	case 0x03:
		if len(data) < i+1 {
			return nil, false
		}
		l := int(data[i])
		i++
		if l == 0 || len(data) < i+l+2 {
			return nil, false
		}
		addrType = "domain"
		addr = string(data[i : i+l])
		i += l
	case 0x04:
		if len(data) < i+16+2 {
			return nil, false
		}
		addrType = "ipv6"
		addr = net.IP(data[i : i+16]).String()
		i += 16
	default:
		return nil, false
	}
	port := int(binary.BigEndian.Uint16(data[i : i+2]))
	i += 2
	return annotateSensitivity(analyzer.PropMap{
		"type":                       "explicit_proxy",
		"class":                      "proxy",
		"protocol":                   "socks5_udp_relay",
		"dst_addr_type":              addrType,
		"dst_addr":                   addr,
		"dst_port":                   port,
		"payload_len":                len(data) - i,
		"client_software_candidates": []string{"clash", "sing-box", "xray"},
	}, 97, []string{"socks5-udp-relay-header"}), true
}

func parseOpenVPNTCP(bs []byte) (m analyzer.PropMap, ok bool, pending bool) {
	if len(bs) < 3 {
		return nil, false, false
	}
	pktLen := int(binary.BigEndian.Uint16(bs[:2]))
	if pktLen < openVPNMinPktLen || pktLen > openVPNMaxPktLen {
		return nil, false, false
	}
	if len(bs) < pktLen+2 {
		return nil, false, true
	}
	opcode := bs[2] >> 3
	if !isOpenVPNOpcode(opcode) {
		return nil, false, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":     "vpn_tunnel",
		"class":    "vpn_tunnel",
		"protocol": "openvpn_tcp",
		"opcode":   int(opcode),
	}, 95, []string{"openvpn-tcp-opcode"}), true, false
}

func parseOpenVPNUDP(data []byte) (analyzer.PropMap, bool) {
	if len(data) == 0 {
		return nil, false
	}
	opcode := data[0] >> 3
	if !isOpenVPNOpcode(opcode) {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":     "vpn_tunnel",
		"class":    "vpn_tunnel",
		"protocol": "openvpn_udp",
		"opcode":   int(opcode),
	}, 95, []string{"openvpn-udp-opcode"}), true
}

func parseWireGuard(data []byte) (analyzer.PropMap, bool) {
	if len(data) < 4 || data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return nil, false
	}
	msgType := data[0]
	switch msgType {
	case wireGuardTypeHandshakeInitiation:
		if len(data) != wireGuardSizeHandshakeInitiation {
			return nil, false
		}
	case wireGuardTypeHandshakeResponse:
		if len(data) != wireGuardSizeHandshakeResponse {
			return nil, false
		}
	case wireGuardTypeData:
		if len(data) < wireGuardMinSizePacketData || len(data)%16 != 0 {
			return nil, false
		}
	case wireGuardTypeCookieReply:
		if len(data) != wireGuardSizePacketCookieReply {
			return nil, false
		}
	default:
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":         "vpn_tunnel",
		"class":        "vpn_tunnel",
		"protocol":     "wireguard",
		"message_type": int(msgType),
	}, 96, []string{"wireguard-message-format"}), true
}

func parseQUICInitialLite(data []byte) (analyzer.PropMap, bool) {
	if len(data) < 1200 || data[0]&0x80 == 0 {
		return nil, false
	}
	version := binary.BigEndian.Uint32(data[1:5])
	if version != 0x00000001 && version != 0x6b3343cf {
		return nil, false
	}
	packetType := (data[0] >> 4) & 0x03
	if version == 0x00000001 && packetType != 0x00 {
		return nil, false
	}
	if version == 0x6b3343cf && packetType != 0x01 {
		return nil, false
	}
	dcidLen := int(data[5])
	if dcidLen > 20 || len(data) < 6+dcidLen+1 {
		return nil, false
	}
	scidLen := int(data[6+dcidLen])
	if scidLen > 20 || len(data) < 7+dcidLen+scidLen {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":       "proxy_candidate",
		"class":      "quic_tunnel",
		"protocol":   "quic_tunnel_candidate",
		"version":    version,
		"candidates": []string{"hysteria2", "tuic", "naiveproxy", "unknown"},
	}, 68, []string{"quic-initial-long-header"}), true
}

func parseTLSProxyFingerprint(bs []byte, cfg FeatureConfig) (m analyzer.PropMap, ok bool, pending bool) {
	if len(bs) < 9 {
		if looksTLSClientHello(bs) {
			return nil, false, true
		}
		return nil, false, false
	}
	if !looksTLSClientHello(bs) {
		return nil, false, false
	}
	recordLen := int(binary.BigEndian.Uint16(bs[3:5]))
	if recordLen < 4 {
		return nil, false, false
	}
	if len(bs) < 5+recordLen {
		return nil, false, true
	}
	if bs[5] != internal.TypeClientHello {
		return nil, false, false
	}
	chLen := int(bs[6])<<16 | int(bs[7])<<8 | int(bs[8])
	if chLen < 41 {
		return nil, false, false
	}
	if len(bs) < 9+chLen {
		return nil, false, true
	}
	chMap := internal.ParseTLSClientHelloMsgData(&utils.ByteBuffer{Buf: bs[9 : 9+chLen]})
	if chMap == nil {
		return nil, false, false
	}
	sni, _ := chMap["sni"].(string)
	alpn := extractALPN(chMap["alpn"])
	proto, candidates, score, signals := inferProxyByTLSMeta(sni, alpn, cfg)
	if proto == "" {
		return nil, false, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":       "proxy_candidate",
		"class":      "tls_tunnel",
		"protocol":   proto,
		"sni":        sni,
		"alpn":       alpn,
		"candidates": candidates,
	}, score, signals), true, false
}

func parseSSHHandshake(bs []byte) (m analyzer.PropMap, ok bool, pending bool) {
	if len(bs) < 4 {
		n := minInt(len(bs), len("SSH-"))
		if strings.HasPrefix("SSH-", string(bs[:n])) {
			return nil, false, true
		}
		return nil, false, false
	}
	if !looksSSH(bs) {
		return nil, false, false
	}
	lineEnd := bytes.Index(bs, []byte("\r\n"))
	if lineEnd < 0 {
		return nil, false, true
	}
	line := string(bs[:lineEnd])
	parts := strings.SplitN(line, "-", 3)
	if len(parts) != 3 {
		return nil, false, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":            "proxy_candidate",
		"class":           "encrypted_tunnel",
		"protocol":        "ssh_tunnel",
		"ssh_protocol":    parts[1],
		"ssh_software":    parts[2],
		"client_greeting": line,
	}, 78, []string{"ssh-binary-protocol"}), true, false
}

func inferProxyByTLSMeta(sni string, alpn []string, cfg FeatureConfig) (protocol string, candidates []string, score int, signals []string) {
	lSNI := strings.ToLower(sni)
	if containsAny(lSNI, cfg.TLS.HysteriaKeywords...) || containsAnySlice(alpn, cfg.TLS.HysteriaKeywords...) {
		return "hysteria2", []string{"hysteria2"}, 94, []string{"tls-sni-or-alpn-hysteria"}
	}
	if containsAny(lSNI, cfg.TLS.TUICKeywords...) || containsAnySlice(alpn, cfg.TLS.TUICKeywords...) {
		return "tuic", []string{"tuic"}, 94, []string{"tls-sni-or-alpn-tuic"}
	}
	if containsAny(lSNI, cfg.TLS.TrojanKeywords...) || containsAnySlice(alpn, cfg.TLS.TrojanKeywords...) {
		return "trojan_like", []string{"trojan", "unknown"}, 90, []string{"tls-sni-or-alpn-trojan"}
	}
	if containsAny(lSNI, cfg.TLS.V2RayKeywords...) ||
		containsAnySlice(alpn, cfg.TLS.V2RayKeywords...) {
		return "v2ray_family_like", []string{"vmess", "vless", "shadowsocks", "unknown"}, 88, []string{"tls-sni-or-alpn-v2ray-family-keyword"}
	}
	if hasUncommonALPN(alpn, cfg) {
		return "tls_proxy_tunnel_like", []string{"unknown"}, 75, []string{"uncommon-tls-alpn"}
	}
	return "", nil, 0, nil
}

func extractALPN(v interface{}) []string {
	ss, ok := v.([]string)
	if !ok || len(ss) == 0 {
		return nil
	}
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func detectEncryptedProxyTCP(bs []byte, cfg FeatureConfig) (analyzer.PropMap, bool) {
	sample := bs[:minInt(len(bs), 256)]
	if looksTLSClientHello(sample) || looksSSH(sample) || looksHTTP(sample) || looksSOCKSPrefix(sample) {
		return nil, false
	}
	entropy := utils.ShannonEntropy(sample)
	printableRatio := utils.PrintableRatio(sample)
	if entropy < cfg.TCPEntropyThreshold || printableRatio > cfg.TCPPrintableThreshold {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":       "proxy_candidate",
		"class":      "encrypted_tunnel",
		"protocol":   "shadowsocks_vmess_like",
		"candidates": []string{"shadowsocks", "vmess", "vless", "unknown"},
		"features": analyzer.PropMap{
			"entropy":         entropy,
			"printable_ratio": printableRatio,
			"sample_len":      len(sample),
		},
	}, encryptedConfidence(entropy, printableRatio), []string{"high-entropy-client-payload", "non-standard-handshake"}), true
}

func detectEncryptedProxyUDP(data []byte, cfg FeatureConfig) (analyzer.PropMap, bool) {
	if len(data) < cfg.UDPEncryptedMinBytes || looksQUICInitial(data) || looksWireGuardType(data) || looksOpenVPNUDPPrefix(data) {
		return nil, false
	}
	sample := data[:minInt(len(data), 256)]
	entropy := utils.ShannonEntropy(sample)
	printableRatio := utils.PrintableRatio(sample)
	if entropy < cfg.UDPEntropyThreshold || printableRatio > cfg.UDPPrintableThreshold {
		return nil, false
	}
	return annotateSensitivity(analyzer.PropMap{
		"type":       "proxy_candidate",
		"class":      "encrypted_tunnel",
		"protocol":   "shadowsocks_vmess_like_udp",
		"candidates": []string{"shadowsocks", "vmess", "vless", "unknown"},
		"features": analyzer.PropMap{
			"entropy":         entropy,
			"printable_ratio": printableRatio,
			"sample_len":      len(sample),
		},
	}, encryptedConfidence(entropy, printableRatio), []string{"high-entropy-udp-payload", "non-standard-udp-header"}), true
}

func splitHostPortLoose(s string) (host string, port int, ok bool) {
	h, p, err := net.SplitHostPort(s)
	if err == nil {
		port, err = strconv.Atoi(p)
		if err == nil {
			return h, port, true
		}
	}
	if strings.Count(s, ":") != 1 {
		return "", 0, false
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i >= len(s)-1 {
		return "", 0, false
	}
	port, err = strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0, false
	}
	return s[:i], port, true
}

func looksTLSClientHello(bs []byte) bool {
	return len(bs) >= 3 && bs[0] >= 0x16 && bs[0] <= 0x17 && bs[1] == 0x03 && bs[2] <= 0x09
}

func looksSSH(bs []byte) bool {
	return len(bs) >= 4 && string(bs[:4]) == "SSH-"
}

func looksSOCKSPrefix(bs []byte) bool {
	return len(bs) > 0 && (bs[0] == 0x04 || bs[0] == 0x05)
}

func looksHTTP(bs []byte) bool {
	methods := [...]string{
		"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "PATCH ",
		"OPTIONS ", "TRACE ", "CONNECT ", "HTTP/",
	}
	s := strings.ToUpper(string(bs[:minInt(len(bs), 10)]))
	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

func looksQUICInitial(data []byte) bool {
	if len(data) < 5 || data[0]&0x80 == 0 {
		return false
	}
	ver := binary.BigEndian.Uint32(data[1:5])
	return ver == 0x00000001 || ver == 0x6b3343cf
}

func looksWireGuardType(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return false
	}
	switch data[0] {
	case 1, 2, 3, 4:
		return true
	default:
		return false
	}
}

func looksOpenVPNUDPPrefix(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	return isOpenVPNOpcode(data[0] >> 3)
}

func encryptedConfidence(entropy, printableRatio float64) int {
	eScore := (entropy - 6.0) / 2.0
	pScore := (0.55 - printableRatio) / 0.55
	if eScore < 0 {
		eScore = 0
	}
	if eScore > 1 {
		eScore = 1
	}
	if pScore < 0 {
		pScore = 0
	}
	if pScore > 1 {
		pScore = 1
	}
	score := int(60 + 20*eScore + 15*pScore)
	if score < 60 {
		return 60
	}
	if score > 95 {
		return 95
	}
	return score
}

func annotateSensitivity(m analyzer.PropMap, score int, signals []string) analyzer.PropMap {
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	m["sensitivity_score"] = score
	m["sensitivity_level"] = sensitivityLevel(score)
	if _, ok := m["confidence"]; !ok {
		m["confidence"] = score
	}
	if len(signals) > 0 {
		m["signals"] = signals
	}
	return m
}

func sensitivityLevel(score int) string {
	if score >= 85 {
		return "high"
	}
	if score >= 70 {
		return "medium"
	}
	return "low"
}

func containsAny(s string, keywords ...string) bool {
	s = strings.ToLower(s)
	for _, k := range keywords {
		if strings.Contains(s, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func containsAnySlice(ss []string, keywords ...string) bool {
	for _, s := range ss {
		if containsAny(s, keywords...) {
			return true
		}
	}
	return false
}

func hasUncommonALPN(alpns []string, cfg FeatureConfig) bool {
	if len(alpns) == 0 {
		return false
	}
	common := make(map[string]struct{}, len(cfg.TLS.CommonALPN))
	for _, a := range cfg.TLS.CommonALPN {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" {
			common[a] = struct{}{}
		}
	}
	for _, a := range alpns {
		al := strings.ToLower(strings.TrimSpace(a))
		if al == "" {
			continue
		}
		if _, ok := common[al]; !ok {
			return true
		}
	}
	return false
}

func isOpenVPNOpcode(opcode byte) bool {
	switch opcode {
	case openVPNControlHardResetClientV1,
		openVPNControlHardResetServerV1,
		openVPNControlSoftResetV1,
		openVPNControlV1,
		openVPNAckV1,
		openVPNDataV1,
		openVPNControlHardResetClientV2,
		openVPNControlHardResetServerV2,
		openVPNDataV2,
		openVPNControlHardResetClientV3,
		openVPNControlWkcV1:
		return true
	default:
		return false
	}
}

func flowKeyTCP(info analyzer.TCPInfo) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(info.SrcIP)
	_, _ = h.Write(info.DstIP)
	var p [4]byte
	binary.BigEndian.PutUint16(p[:2], info.SrcPort)
	binary.BigEndian.PutUint16(p[2:], info.DstPort)
	_, _ = h.Write(p[:])
	return h.Sum64()
}

func flowKeyUDP(info analyzer.UDPInfo) uint64 {
	h := fnv.New64a()
	_, _ = h.Write(info.SrcIP)
	_, _ = h.Write(info.DstIP)
	var p [4]byte
	binary.BigEndian.PutUint16(p[:2], info.SrcPort)
	binary.BigEndian.PutUint16(p[2:], info.DstPort)
	_, _ = h.Write(p[:])
	return h.Sum64()
}

func inGray(key uint64, percent int) bool {
	if percent >= 100 {
		return true
	}
	return int(key%100) < percent
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
