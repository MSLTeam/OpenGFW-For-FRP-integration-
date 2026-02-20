package traffic

import (
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type MinecraftFeatureConfig struct {
	JavaServerPorts    []int `yaml:"javaServerPorts"`
	BedrockServerPorts []int `yaml:"bedrockServerPorts"`
}

type ServiceTagConfig struct {
	Name       string `yaml:"name"`
	Family     string `yaml:"family"`
	Role       string `yaml:"role"`
	Transport  string `yaml:"transport"` // tcp / udp / any
	Ports      []int  `yaml:"ports"`
	Confidence int    `yaml:"confidence"`
}

type FeatureConfig struct {
	GrayPercent              int                    `yaml:"grayPercent"`
	TCPScanLimit             int                    `yaml:"tcpScanLimit"`
	UDPInvalidCountThreshold int                    `yaml:"udpInvalidCountThreshold"`
	BuiltinPortTagEnabled    bool                   `yaml:"builtinPortTagEnabled"`
	Minecraft                MinecraftFeatureConfig `yaml:"minecraft"`
	ServiceTags              []ServiceTagConfig     `yaml:"serviceTags"`
}

func defaultFeatureConfig() FeatureConfig {
	return FeatureConfig{
		GrayPercent:              100,
		TCPScanLimit:             1024,
		UDPInvalidCountThreshold: 4,
		BuiltinPortTagEnabled:    true,
		Minecraft: MinecraftFeatureConfig{
			JavaServerPorts:    []int{25565},
			BedrockServerPorts: []int{19132, 19133},
		},
	}
}

func (c FeatureConfig) clone() FeatureConfig {
	out := c
	out.Minecraft.JavaServerPorts = append([]int(nil), c.Minecraft.JavaServerPorts...)
	out.Minecraft.BedrockServerPorts = append([]int(nil), c.Minecraft.BedrockServerPorts...)
	out.ServiceTags = append([]ServiceTagConfig(nil), c.ServiceTags...)
	return out
}

func (c *FeatureConfig) normalize() {
	def := defaultFeatureConfig()
	if c.GrayPercent <= 0 || c.GrayPercent > 100 {
		c.GrayPercent = def.GrayPercent
	}
	if c.TCPScanLimit <= 0 {
		c.TCPScanLimit = def.TCPScanLimit
	}
	if c.UDPInvalidCountThreshold <= 0 {
		c.UDPInvalidCountThreshold = def.UDPInvalidCountThreshold
	}

	c.Minecraft.JavaServerPorts = normalizePorts(c.Minecraft.JavaServerPorts, def.Minecraft.JavaServerPorts)
	c.Minecraft.BedrockServerPorts = normalizePorts(c.Minecraft.BedrockServerPorts, def.Minecraft.BedrockServerPorts)
	c.ServiceTags = normalizeServiceTags(c.ServiceTags)
}

func normalizePorts(in []int, fallback []int) []int {
	if len(in) == 0 {
		return append([]int(nil), fallback...)
	}
	seen := make(map[int]struct{}, len(in))
	out := make([]int, 0, len(in))
	for _, p := range in {
		if p <= 0 || p > 65535 {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	if len(out) == 0 {
		return append([]int(nil), fallback...)
	}
	return out
}

func normalizeServiceTags(in []ServiceTagConfig) []ServiceTagConfig {
	if len(in) == 0 {
		return nil
	}
	out := make([]ServiceTagConfig, 0, len(in))
	for _, tag := range in {
		tag.Name = strings.TrimSpace(tag.Name)
		if tag.Name == "" {
			continue
		}
		tag.Family = strings.TrimSpace(tag.Family)
		if tag.Family == "" {
			tag.Family = "custom_service"
		}
		tag.Role = strings.TrimSpace(tag.Role)
		if tag.Role == "" {
			tag.Role = "service"
		}
		switch strings.ToLower(strings.TrimSpace(tag.Transport)) {
		case "tcp", "udp":
			tag.Transport = strings.ToLower(strings.TrimSpace(tag.Transport))
		default:
			tag.Transport = "any"
		}
		tag.Ports = normalizePorts(tag.Ports, nil)
		if len(tag.Ports) == 0 {
			continue
		}
		if tag.Confidence <= 0 || tag.Confidence > 100 {
			tag.Confidence = 75
		}
		out = append(out, tag)
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

type TrafficAnalyzer struct {
	mu          sync.RWMutex
	cfg         FeatureConfig
	featureFile string
}

func NewTrafficAnalyzer() *TrafficAnalyzer {
	cfg := defaultFeatureConfig()
	return &TrafficAnalyzer{cfg: cfg}
}

func (a *TrafficAnalyzer) getFeatureConfig() FeatureConfig {
	a.mu.RLock()
	cfg := a.cfg
	a.mu.RUnlock()
	if cfg.TCPScanLimit == 0 {
		a.mu.Lock()
		if a.cfg.TCPScanLimit == 0 {
			a.cfg = defaultFeatureConfig()
		}
		cfg = a.cfg
		a.mu.Unlock()
	}
	return cfg.clone()
}

func (a *TrafficAnalyzer) SetFeatureFile(path string) error {
	path = strings.TrimSpace(path)
	cfg, err := LoadFeatureConfig(path)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.cfg = cfg
	a.featureFile = path
	a.mu.Unlock()
	return nil
}

func (a *TrafficAnalyzer) ReloadFeatures() error {
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
	a.mu.Unlock()
	return nil
}

func (a *TrafficAnalyzer) HasFeatureFile() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.featureFile != ""
}
