package frp

import (
	"fmt"
	"net"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/proxy"
	"github.com/apernet/OpenGFW/analyzer/traffic"
)

type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionBlock Action = "block"
)

type ProxyPolicy struct {
	Enabled         bool
	HighThreshold   int
	MediumThreshold int
}

type TrafficPolicy struct {
	Enabled     bool
	BlockWebTCP bool
}

type Config struct {
	ProxyFeatureFile   string
	TrafficFeatureFile string
	ProxyPolicy        ProxyPolicy
	TrafficPolicy      TrafficPolicy
}

func DefaultConfig() Config {
	return Config{
		ProxyPolicy: ProxyPolicy{
			Enabled:         true,
			HighThreshold:   85,
			MediumThreshold: 70,
		},
		TrafficPolicy: TrafficPolicy{
			Enabled:     true,
			BlockWebTCP: true,
		},
	}
}

type StreamMeta struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
}

func (m StreamMeta) Validate() error {
	if m.SrcIP == nil {
		return fmt.Errorf("src ip is nil")
	}
	if m.DstIP == nil {
		return fmt.Errorf("dst ip is nil")
	}
	return nil
}

func (m StreamMeta) clone() StreamMeta {
	out := m
	out.SrcIP = append(net.IP(nil), m.SrcIP...)
	out.DstIP = append(net.IP(nil), m.DstIP...)
	return out
}

func (m StreamMeta) tcpInfo() analyzer.TCPInfo {
	return analyzer.TCPInfo{
		SrcIP:   append(net.IP(nil), m.SrcIP...),
		DstIP:   append(net.IP(nil), m.DstIP...),
		SrcPort: m.SrcPort,
		DstPort: m.DstPort,
	}
}

func (m StreamMeta) udpInfo() analyzer.UDPInfo {
	return analyzer.UDPInfo{
		SrcIP:   append(net.IP(nil), m.SrcIP...),
		DstIP:   append(net.IP(nil), m.DstIP...),
		SrcPort: m.SrcPort,
		DstPort: m.DstPort,
	}
}

type ProxyReport struct {
	Protocol         string
	Type             string
	Class            string
	SensitivityScore int
	SensitivityLevel string
	Raw              analyzer.PropMap
}

type TrafficReport struct {
	Label      string
	Family     string
	Role       string
	Method     string
	Transport  string
	Confidence int
	Raw        analyzer.PropMap
}

type InspectionReport struct {
	Updated bool
	Done    bool

	Action Action
	Reason string

	Proxy   *ProxyReport
	Traffic *TrafficReport
}

type Engine struct {
	proxyAnalyzer   *proxy.ProxyAnalyzer
	trafficAnalyzer *traffic.TrafficAnalyzer
	proxyPolicy     ProxyPolicy
	trafficPolicy   TrafficPolicy
}

func NewEngine(cfg Config) (*Engine, error) {
	cfg.ProxyPolicy = normalizeProxyPolicy(defaultProxyPolicyIfZero(cfg.ProxyPolicy))
	cfg.TrafficPolicy = normalizeTrafficPolicy(defaultTrafficPolicyIfZero(cfg.TrafficPolicy))

	pa := proxy.NewProxyAnalyzer()
	if err := pa.SetFeatureFile(cfg.ProxyFeatureFile); err != nil {
		return nil, fmt.Errorf("load proxy features: %w", err)
	}
	ta := traffic.NewTrafficAnalyzer()
	if err := ta.SetFeatureFile(cfg.TrafficFeatureFile); err != nil {
		return nil, fmt.Errorf("load traffic features: %w", err)
	}
	return &Engine{
		proxyAnalyzer:   pa,
		trafficAnalyzer: ta,
		proxyPolicy:     cfg.ProxyPolicy,
		trafficPolicy:   cfg.TrafficPolicy,
	}, nil
}

func (e *Engine) ReloadFeatures() error {
	if err := e.proxyAnalyzer.ReloadFeatures(); err != nil {
		return err
	}
	if err := e.trafficAnalyzer.ReloadFeatures(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) SetProxyFeatureFile(path string) error {
	return e.proxyAnalyzer.SetFeatureFile(path)
}

func (e *Engine) SetTrafficFeatureFile(path string) error {
	return e.trafficAnalyzer.SetFeatureFile(path)
}

func (e *Engine) SetProxyPolicy(policy ProxyPolicy) {
	e.proxyPolicy = normalizeProxyPolicy(policy)
}

func (e *Engine) SetTrafficPolicy(policy TrafficPolicy) {
	e.trafficPolicy = normalizeTrafficPolicy(policy)
}

func (e *Engine) NewTCPStream(meta StreamMeta) (*TCPStream, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	meta = meta.clone()
	return &TCPStream{
		meta:          meta,
		proxyPolicy:   e.proxyPolicy,
		trafficPolicy: e.trafficPolicy,
		proxy:         e.proxyAnalyzer.NewTCP(meta.tcpInfo(), nil),
		traffic:       e.trafficAnalyzer.NewTCP(meta.tcpInfo(), nil),
	}, nil
}

func (e *Engine) NewUDPStream(meta StreamMeta) (*UDPStream, error) {
	if err := meta.Validate(); err != nil {
		return nil, err
	}
	meta = meta.clone()
	return &UDPStream{
		meta:          meta,
		proxyPolicy:   e.proxyPolicy,
		trafficPolicy: e.trafficPolicy,
		proxy:         e.proxyAnalyzer.NewUDP(meta.udpInfo(), nil),
		traffic:       e.trafficAnalyzer.NewUDP(meta.udpInfo(), nil),
	}, nil
}

type TCPStream struct {
	meta          StreamMeta
	proxyPolicy   ProxyPolicy
	trafficPolicy TrafficPolicy

	proxy   analyzer.TCPStream
	traffic analyzer.TCPStream

	proxyDone   bool
	trafficDone bool

	lastProxy   analyzer.PropMap
	lastTraffic analyzer.PropMap
}

func (s *TCPStream) Feed(rev, start, end bool, skip int, data []byte) InspectionReport {
	updated := false

	if !s.proxyDone && s.proxy != nil {
		u, done := s.proxy.Feed(rev, start, end, skip, data)
		if u != nil && u.M != nil {
			s.lastProxy = clonePropMap(u.M)
			updated = true
		}
		if done {
			s.proxyDone = true
		}
	}
	if !s.trafficDone && s.traffic != nil {
		u, done := s.traffic.Feed(rev, start, end, skip, data)
		if u != nil && u.M != nil {
			s.lastTraffic = clonePropMap(u.M)
			updated = true
		}
		if done {
			s.trafficDone = true
		}
	}
	rep := s.buildReport(updated)
	rep.Done = s.proxyDone && s.trafficDone
	return rep
}

func (s *TCPStream) Close(limited bool) InspectionReport {
	updated := false
	if !s.proxyDone && s.proxy != nil {
		if u := s.proxy.Close(limited); u != nil && u.M != nil {
			s.lastProxy = clonePropMap(u.M)
			updated = true
		}
		s.proxyDone = true
	}
	if !s.trafficDone && s.traffic != nil {
		if u := s.traffic.Close(limited); u != nil && u.M != nil {
			s.lastTraffic = clonePropMap(u.M)
			updated = true
		}
		s.trafficDone = true
	}
	rep := s.buildReport(updated)
	rep.Done = true
	return rep
}

func (s *TCPStream) buildReport(updated bool) InspectionReport {
	pr := parseProxyReport(s.lastProxy)
	tr := parseTrafficReport(s.lastTraffic)
	action, reason := decideAction(pr, tr, s.proxyPolicy, s.trafficPolicy)
	return InspectionReport{
		Updated: updated,
		Action:  action,
		Reason:  reason,
		Proxy:   pr,
		Traffic: tr,
	}
}

type UDPStream struct {
	meta          StreamMeta
	proxyPolicy   ProxyPolicy
	trafficPolicy TrafficPolicy

	proxy   analyzer.UDPStream
	traffic analyzer.UDPStream

	proxyDone   bool
	trafficDone bool

	lastProxy   analyzer.PropMap
	lastTraffic analyzer.PropMap
}

func (s *UDPStream) Feed(rev bool, data []byte) InspectionReport {
	updated := false

	if !s.proxyDone && s.proxy != nil {
		u, done := s.proxy.Feed(rev, data)
		if u != nil && u.M != nil {
			s.lastProxy = clonePropMap(u.M)
			updated = true
		}
		if done {
			s.proxyDone = true
		}
	}
	if !s.trafficDone && s.traffic != nil {
		u, done := s.traffic.Feed(rev, data)
		if u != nil && u.M != nil {
			s.lastTraffic = clonePropMap(u.M)
			updated = true
		}
		if done {
			s.trafficDone = true
		}
	}
	rep := s.buildReport(updated)
	rep.Done = s.proxyDone && s.trafficDone
	return rep
}

func (s *UDPStream) Close(limited bool) InspectionReport {
	updated := false
	if !s.proxyDone && s.proxy != nil {
		if u := s.proxy.Close(limited); u != nil && u.M != nil {
			s.lastProxy = clonePropMap(u.M)
			updated = true
		}
		s.proxyDone = true
	}
	if !s.trafficDone && s.traffic != nil {
		if u := s.traffic.Close(limited); u != nil && u.M != nil {
			s.lastTraffic = clonePropMap(u.M)
			updated = true
		}
		s.trafficDone = true
	}
	rep := s.buildReport(updated)
	rep.Done = true
	return rep
}

func (s *UDPStream) buildReport(updated bool) InspectionReport {
	pr := parseProxyReport(s.lastProxy)
	tr := parseTrafficReport(s.lastTraffic)
	action, reason := decideAction(pr, tr, s.proxyPolicy, s.trafficPolicy)
	return InspectionReport{
		Updated: updated,
		Action:  action,
		Reason:  reason,
		Proxy:   pr,
		Traffic: tr,
	}
}

func normalizeProxyPolicy(in ProxyPolicy) ProxyPolicy {
	if in.HighThreshold <= 0 || in.HighThreshold > 100 {
		in.HighThreshold = 85
	}
	if in.MediumThreshold <= 0 || in.MediumThreshold >= in.HighThreshold {
		in.MediumThreshold = 70
		if in.MediumThreshold >= in.HighThreshold {
			in.MediumThreshold = in.HighThreshold - 1
		}
		if in.MediumThreshold <= 0 {
			in.MediumThreshold = 1
		}
	}
	return in
}

func defaultProxyPolicyIfZero(in ProxyPolicy) ProxyPolicy {
	if in == (ProxyPolicy{}) {
		return DefaultConfig().ProxyPolicy
	}
	return in
}

func normalizeTrafficPolicy(in TrafficPolicy) TrafficPolicy {
	return in
}

func defaultTrafficPolicyIfZero(in TrafficPolicy) TrafficPolicy {
	if in == (TrafficPolicy{}) {
		return DefaultConfig().TrafficPolicy
	}
	return in
}

func parseProxyReport(m analyzer.PropMap) *ProxyReport {
	if m == nil {
		return nil
	}
	p := &ProxyReport{
		Protocol:         toString(m["protocol"]),
		Type:             toString(m["type"]),
		Class:            toString(m["class"]),
		SensitivityScore: toInt(m["sensitivity_score"]),
		SensitivityLevel: toString(m["sensitivity_level"]),
		Raw:              clonePropMap(m),
	}
	if p.Protocol == "" && p.Type == "" && p.SensitivityScore == 0 {
		return nil
	}
	return p
}

func parseTrafficReport(m analyzer.PropMap) *TrafficReport {
	if m == nil {
		return nil
	}
	t := &TrafficReport{
		Label:      toString(m["label"]),
		Family:     toString(m["family"]),
		Role:       toString(m["role"]),
		Method:     toString(m["method"]),
		Transport:  toString(m["transport"]),
		Confidence: toInt(m["confidence"]),
		Raw:        clonePropMap(m),
	}
	if t.Label == "" && t.Family == "" && t.Confidence == 0 {
		return nil
	}
	return t
}

func decideAction(pr *ProxyReport, tr *TrafficReport, pp ProxyPolicy, tp TrafficPolicy) (Action, string) {
	if pp.Enabled && pr != nil && pr.Protocol == "source_ip_penalty" {
		return ActionBlock, "source ip penalty"
	}
	if trafficPolicyBlockWebTCP(tr, tp) {
		return ActionBlock, "traffic policy block web tcp"
	}
	return decideProxyAction(pr, pp)
}

func trafficPolicyBlockWebTCP(tr *TrafficReport, policy TrafficPolicy) bool {
	if !policy.Enabled || !policy.BlockWebTCP {
		return false
	}
	if tr == nil {
		return false
	}
	if tr.Transport != "tcp" {
		return false
	}
	if tr.Label == "Web Service (HTTP)" || tr.Label == "Web Service (HTTPS/TLS)" {
		return true
	}
	return false
}

func decideProxyAction(pr *ProxyReport, policy ProxyPolicy) (Action, string) {
	if !policy.Enabled {
		return ActionAllow, "proxy policy disabled"
	}
	if pr == nil {
		return ActionAllow, "no proxy signal"
	}
	if pr.Protocol == "source_ip_penalty" {
		return ActionBlock, "source ip penalty"
	}
	score := pr.SensitivityScore
	switch {
	case score >= policy.HighThreshold:
		return ActionBlock, "high similarity"
	case score >= policy.MediumThreshold:
		return ActionWarn, "medium similarity"
	case score > 0:
		return ActionWarn, "low similarity"
	default:
		return ActionAllow, "no similarity"
	}
}

func clonePropMap(in analyzer.PropMap) analyzer.PropMap {
	if in == nil {
		return nil
	}
	out := make(analyzer.PropMap, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func toString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func toInt(v interface{}) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case uint64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}
