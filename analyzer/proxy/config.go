package proxy

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type TLSFeatureConfig struct {
	HysteriaKeywords []string `yaml:"hysteriaKeywords"`
	TUICKeywords     []string `yaml:"tuicKeywords"`
	TrojanKeywords   []string `yaml:"trojanKeywords"`
	V2RayKeywords    []string `yaml:"v2rayKeywords"`
	CommonALPN       []string `yaml:"commonALPN"`
}

type FeatureConfig struct {
	GrayPercent int `yaml:"grayPercent"`

	SourcePenaltyEnabled      bool `yaml:"sourcePenaltyEnabled"`
	SourcePenaltyTTLSeconds   int  `yaml:"sourcePenaltyTTLSeconds"`
	SourcePenaltyTriggerScore int  `yaml:"sourcePenaltyTriggerScore"`
	SourcePenaltyBlockScore   int  `yaml:"sourcePenaltyBlockScore"`
	SourcePenaltyMaxEntries   int  `yaml:"sourcePenaltyMaxEntries"`

	TCPEncryptedMinBytes  int     `yaml:"tcpEncryptedMinBytes"`
	TCPEntropyThreshold   float64 `yaml:"tcpEntropyThreshold"`
	TCPPrintableThreshold float64 `yaml:"tcpPrintableThreshold"`

	UDPInvalidCountThreshold int     `yaml:"udpInvalidCountThreshold"`
	UDPEncryptedMinBytes     int     `yaml:"udpEncryptedMinBytes"`
	UDPEntropyThreshold      float64 `yaml:"udpEntropyThreshold"`
	UDPPrintableThreshold    float64 `yaml:"udpPrintableThreshold"`

	TLS TLSFeatureConfig `yaml:"tls"`
}

func defaultFeatureConfig() FeatureConfig {
	return FeatureConfig{
		GrayPercent:               100,
		SourcePenaltyEnabled:      true,
		SourcePenaltyTTLSeconds:   600,
		SourcePenaltyTriggerScore: 85,
		SourcePenaltyBlockScore:   100,
		SourcePenaltyMaxEntries:   65536,
		TCPEncryptedMinBytes:      proxyTCPEncryptedMinBytes,
		TCPEntropyThreshold:       proxyTCPEntropyThreshold,
		TCPPrintableThreshold:     proxyTCPPrintableThreshold,
		UDPInvalidCountThreshold:  proxyUDPInvalidCountThreshold,
		UDPEncryptedMinBytes:      proxyUDPEncryptedMinBytes,
		UDPEntropyThreshold:       proxyUDPEntropyThreshold,
		UDPPrintableThreshold:     proxyUDPPrintableThreshold,
		TLS: TLSFeatureConfig{
			HysteriaKeywords: []string{"hysteria", "hy2"},
			TUICKeywords:     []string{"tuic"},
			TrojanKeywords:   []string{"trojan"},
			V2RayKeywords:    []string{"vmess", "vless", "v2ray", "xray", "sing-box", "clash", "shadow", "shadowsocks"},
			CommonALPN:       []string{"h2", "h3", "h3-29", "h3-32", "h3-34", "http/1.1", "acme-tls/1"},
		},
	}
}

func (c FeatureConfig) clone() FeatureConfig {
	out := c
	out.TLS.HysteriaKeywords = append([]string(nil), c.TLS.HysteriaKeywords...)
	out.TLS.TUICKeywords = append([]string(nil), c.TLS.TUICKeywords...)
	out.TLS.TrojanKeywords = append([]string(nil), c.TLS.TrojanKeywords...)
	out.TLS.V2RayKeywords = append([]string(nil), c.TLS.V2RayKeywords...)
	out.TLS.CommonALPN = append([]string(nil), c.TLS.CommonALPN...)
	return out
}

func (c *FeatureConfig) normalize() {
	def := defaultFeatureConfig()
	if c.GrayPercent <= 0 || c.GrayPercent > 100 {
		c.GrayPercent = def.GrayPercent
	}
	if c.SourcePenaltyTTLSeconds <= 0 {
		c.SourcePenaltyTTLSeconds = def.SourcePenaltyTTLSeconds
	}
	if c.SourcePenaltyTriggerScore <= 0 || c.SourcePenaltyTriggerScore > 100 {
		c.SourcePenaltyTriggerScore = def.SourcePenaltyTriggerScore
	}
	if c.SourcePenaltyBlockScore <= 0 || c.SourcePenaltyBlockScore > 100 {
		c.SourcePenaltyBlockScore = def.SourcePenaltyBlockScore
	}
	if c.SourcePenaltyMaxEntries <= 0 {
		c.SourcePenaltyMaxEntries = def.SourcePenaltyMaxEntries
	}

	if c.TCPEncryptedMinBytes <= 0 {
		c.TCPEncryptedMinBytes = def.TCPEncryptedMinBytes
	}
	if c.TCPEntropyThreshold <= 0 {
		c.TCPEntropyThreshold = def.TCPEntropyThreshold
	}
	if c.TCPPrintableThreshold <= 0 || c.TCPPrintableThreshold > 1 {
		c.TCPPrintableThreshold = def.TCPPrintableThreshold
	}

	if c.UDPInvalidCountThreshold <= 0 {
		c.UDPInvalidCountThreshold = def.UDPInvalidCountThreshold
	}
	if c.UDPEncryptedMinBytes <= 0 {
		c.UDPEncryptedMinBytes = def.UDPEncryptedMinBytes
	}
	if c.UDPEntropyThreshold <= 0 {
		c.UDPEntropyThreshold = def.UDPEntropyThreshold
	}
	if c.UDPPrintableThreshold <= 0 || c.UDPPrintableThreshold > 1 {
		c.UDPPrintableThreshold = def.UDPPrintableThreshold
	}

	if len(c.TLS.HysteriaKeywords) == 0 {
		c.TLS.HysteriaKeywords = def.TLS.HysteriaKeywords
	}
	if len(c.TLS.TUICKeywords) == 0 {
		c.TLS.TUICKeywords = def.TLS.TUICKeywords
	}
	if len(c.TLS.TrojanKeywords) == 0 {
		c.TLS.TrojanKeywords = def.TLS.TrojanKeywords
	}
	if len(c.TLS.V2RayKeywords) == 0 {
		c.TLS.V2RayKeywords = def.TLS.V2RayKeywords
	}
	if len(c.TLS.CommonALPN) == 0 {
		c.TLS.CommonALPN = def.TLS.CommonALPN
	}

	c.TLS.HysteriaKeywords = normalizeKeywordList(c.TLS.HysteriaKeywords)
	c.TLS.TUICKeywords = normalizeKeywordList(c.TLS.TUICKeywords)
	c.TLS.TrojanKeywords = normalizeKeywordList(c.TLS.TrojanKeywords)
	c.TLS.V2RayKeywords = normalizeKeywordList(c.TLS.V2RayKeywords)
	c.TLS.CommonALPN = normalizeKeywordList(c.TLS.CommonALPN)
}

func normalizeKeywordList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func LoadFeatureConfig(path string) (FeatureConfig, error) {
	cfg := defaultFeatureConfig()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	bs, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	if err := yaml.Unmarshal(bs, &cfg); err != nil {
		return cfg, err
	}
	cfg.normalize()
	return cfg, nil
}

func NewProxyAnalyzer() *ProxyAnalyzer {
	cfg := defaultFeatureConfig()
	return &ProxyAnalyzer{
		cfg:     cfg,
		penalty: newSourcePenaltyCache(cfg),
	}
}

func (a *ProxyAnalyzer) getFeatureConfig() FeatureConfig {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if cfg.TCPEncryptedMinBytes == 0 {
		a.mu.Lock()
		if a.cfg.TCPEncryptedMinBytes == 0 {
			a.cfg = defaultFeatureConfig()
		}
		cfg = a.cfg
		a.mu.Unlock()
	}
	return cfg.clone()
}

func (a *ProxyAnalyzer) SetFeatureFile(path string) error {
	path = strings.TrimSpace(path)
	cfg, err := LoadFeatureConfig(path)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.featureFile = path
	if a.penalty != nil {
		a.penalty.Configure(cfg)
	}
	a.mu.Unlock()
	return nil
}

func (a *ProxyAnalyzer) ReloadFeatures() error {
	a.mu.RLock()
	path := a.featureFile
	a.mu.RUnlock()
	if path == "" {
		return nil
	}
	cfg, err := LoadFeatureConfig(path)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	if a.penalty != nil {
		a.penalty.Configure(cfg)
	}
	a.mu.Unlock()
	return nil
}

func (a *ProxyAnalyzer) HasFeatureFile() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.featureFile != ""
}
