package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/proxy"
	"github.com/apernet/OpenGFW/analyzer/tcp"
	"github.com/apernet/OpenGFW/analyzer/traffic"
	"github.com/apernet/OpenGFW/analyzer/udp"
	"github.com/apernet/OpenGFW/engine"
	"github.com/apernet/OpenGFW/io"
	"github.com/apernet/OpenGFW/modifier"
	modUDP "github.com/apernet/OpenGFW/modifier/udp"
	"github.com/apernet/OpenGFW/ruleset"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	appLogo = `
░█▀█░█▀█░█▀▀░█▀█░█▀▀░█▀▀░█░█
░█░█░█▀▀░█▀▀░█░█░█░█░█▀▀░█▄█
░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░▀░░░▀░▀
`
	appDesc    = "Open source network filtering and analysis software"
	appAuthors = "Aperture Internet Laboratory <https://github.com/apernet>"

	appLogLevelEnv  = "OPENGFW_LOG_LEVEL"
	appLogFormatEnv = "OPENGFW_LOG_FORMAT"
)

var logger *zap.Logger

// Flags
var (
	cfgFile   string
	logLevel  string
	logFormat string
)

var rootCmd = &cobra.Command{
	Use:   "OpenGFW [flags] rule_file",
	Short: appDesc,
	Args:  cobra.ExactArgs(1),
	Run:   runMain,
}

var logLevelMap = map[string]zapcore.Level{
	"debug": zapcore.DebugLevel,
	"info":  zapcore.InfoLevel,
	"warn":  zapcore.WarnLevel,
	"error": zapcore.ErrorLevel,
}

var logFormatMap = map[string]zapcore.EncoderConfig{
	"console": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.RFC3339TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
	"json": {
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		MessageKey:     "msg",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.EpochMillisTimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
	},
}

// Analyzers & modifiers

var proxyAnalyzer = proxy.NewProxyAnalyzer()
var trafficAnalyzer = traffic.NewTrafficAnalyzer()

var analyzers = []analyzer.Analyzer{
	proxyAnalyzer,
	trafficAnalyzer,
	&tcp.FETAnalyzer{},
	&tcp.HTTPAnalyzer{},
	&tcp.SocksAnalyzer{},
	&tcp.SSHAnalyzer{},
	&tcp.TLSAnalyzer{},
	&tcp.TrojanAnalyzer{},
	&udp.DNSAnalyzer{},
	&udp.OpenVPNAnalyzer{},
	&udp.QUICAnalyzer{},
	&udp.WireGuardAnalyzer{},
}

var modifiers = []modifier.Modifier{
	&modUDP.DNSModifier{},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	initFlags()
	cobra.OnInitialize(initConfig)
	cobra.OnInitialize(initLogger) // initLogger must come after initConfig as it depends on config
}

func initFlags() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "l", envOrDefaultString(appLogLevelEnv, "info"), "log level")
	rootCmd.PersistentFlags().StringVarP(&logFormat, "log-format", "f", envOrDefaultString(appLogFormatEnv, "console"), "log format")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.SupportedExts = append([]string{"yaml", "yml"}, viper.SupportedExts...)
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.opengfw")
		viper.AddConfigPath("/etc/opengfw")
	}
}

func initLogger() {
	level, ok := logLevelMap[strings.ToLower(logLevel)]
	if !ok {
		fmt.Printf("unsupported log level: %s\n", logLevel)
		os.Exit(1)
	}
	enc, ok := logFormatMap[strings.ToLower(logFormat)]
	if !ok {
		fmt.Printf("unsupported log format: %s\n", logFormat)
		os.Exit(1)
	}
	c := zap.Config{
		Level:             zap.NewAtomicLevelAt(level),
		DisableCaller:     true,
		DisableStacktrace: true,
		Encoding:          strings.ToLower(logFormat),
		EncoderConfig:     enc,
		OutputPaths:       []string{"stderr"},
		ErrorOutputPaths:  []string{"stderr"},
	}
	var err error
	logger, err = c.Build()
	if err != nil {
		fmt.Printf("failed to initialize logger: %s\n", err)
		os.Exit(1)
	}
}

type cliConfig struct {
	IO      cliConfigIO      `mapstructure:"io"`
	Workers cliConfigWorkers `mapstructure:"workers"`
	Ruleset cliConfigRuleset `mapstructure:"ruleset"`
	Proxy   cliConfigProxy   `mapstructure:"proxy"`
	Traffic cliConfigTraffic `mapstructure:"traffic"`
}

type cliConfigIO struct {
	QueueSize   uint32 `mapstructure:"queueSize"`
	ReadBuffer  int    `mapstructure:"rcvBuf"`
	WriteBuffer int    `mapstructure:"sndBuf"`
	Local       bool   `mapstructure:"local"`
	RST         bool   `mapstructure:"rst"`
}

type cliConfigWorkers struct {
	Count                      int `mapstructure:"count"`
	QueueSize                  int `mapstructure:"queueSize"`
	TCPMaxBufferedPagesTotal   int `mapstructure:"tcpMaxBufferedPagesTotal"`
	TCPMaxBufferedPagesPerConn int `mapstructure:"tcpMaxBufferedPagesPerConn"`
	UDPMaxStreams              int `mapstructure:"udpMaxStreams"`
}

type cliConfigRuleset struct {
	GeoIp   string `mapstructure:"geoip"`
	GeoSite string `mapstructure:"geosite"`
}

type cliConfigProxy struct {
	Features string               `mapstructure:"features"`
	Policy   cliConfigProxyPolicy `mapstructure:"policy"`
}

type cliConfigProxyPolicy struct {
	Enabled         *bool `mapstructure:"enabled"`
	HighThreshold   int   `mapstructure:"highThreshold"`
	MediumThreshold int   `mapstructure:"mediumThreshold"`
}

type proxyPolicyConfig struct {
	Enabled         bool
	HighThreshold   int
	MediumThreshold int
}

type cliConfigTraffic struct {
	Features string                 `mapstructure:"features"`
	Policy   cliConfigTrafficPolicy `mapstructure:"policy"`
}

type cliConfigTrafficPolicy struct {
	Enabled *bool `mapstructure:"enabled"`
}

type trafficPolicyConfig struct {
	Enabled bool
}

func (c *cliConfig) fillLogger(config *engine.Config) error {
	config.Logger = &engineLogger{}
	return nil
}

func (c *cliConfig) fillIO(config *engine.Config) error {
	nfio, err := io.NewNFQueuePacketIO(io.NFQueuePacketIOConfig{
		QueueSize:   c.IO.QueueSize,
		ReadBuffer:  c.IO.ReadBuffer,
		WriteBuffer: c.IO.WriteBuffer,
		Local:       c.IO.Local,
		RST:         c.IO.RST,
	})
	if err != nil {
		return configError{Field: "io", Err: err}
	}
	config.IO = nfio
	return nil
}

func (c *cliConfig) fillWorkers(config *engine.Config) error {
	config.Workers = c.Workers.Count
	config.WorkerQueueSize = c.Workers.QueueSize
	config.WorkerTCPMaxBufferedPagesTotal = c.Workers.TCPMaxBufferedPagesTotal
	config.WorkerTCPMaxBufferedPagesPerConn = c.Workers.TCPMaxBufferedPagesPerConn
	config.WorkerUDPMaxStreams = c.Workers.UDPMaxStreams
	return nil
}

// Config validates the fields and returns a ready-to-use engine config.
// This does not include the ruleset.
func (c *cliConfig) Config() (*engine.Config, error) {
	engineConfig := &engine.Config{}
	fillers := []func(*engine.Config) error{
		c.fillLogger,
		c.fillIO,
		c.fillWorkers,
	}
	for _, f := range fillers {
		if err := f(engineConfig); err != nil {
			return nil, err
		}
	}
	return engineConfig, nil
}

func runMain(cmd *cobra.Command, args []string) {
	// Config
	if err := viper.ReadInConfig(); err != nil {
		logger.Fatal("failed to read config", zap.Error(err))
	}
	var config cliConfig
	if err := viper.Unmarshal(&config); err != nil {
		logger.Fatal("failed to parse config", zap.Error(err))
	}
	engineConfig, err := config.Config()
	if err != nil {
		logger.Fatal("failed to parse config", zap.Error(err))
	}
	defer engineConfig.IO.Close() // Make sure to close IO on exit

	if err := proxyAnalyzer.SetFeatureFile(config.Proxy.Features); err != nil {
		logger.Fatal("failed to load proxy features", zap.Error(err))
	}
	if proxyAnalyzer.HasFeatureFile() {
		logger.Info("proxy features loaded", zap.String("file", config.Proxy.Features))
	}
	if err := trafficAnalyzer.SetFeatureFile(config.Traffic.Features); err != nil {
		logger.Fatal("failed to load traffic features", zap.Error(err))
	}
	if trafficAnalyzer.HasFeatureFile() {
		logger.Info("traffic features loaded", zap.String("file", config.Traffic.Features))
	}

	// Ruleset
	rawRs, err := ruleset.ExprRulesFromYAML(args[0])
	if err != nil {
		logger.Fatal("failed to load rules", zap.Error(err))
	}
	ppCfg := normalizeProxyPolicy(config.Proxy.Policy)
	if ppCfg.Enabled {
		rawRs = withProxyPolicyRules(rawRs, ppCfg)
		logger.Info("proxy policy enabled",
			zap.Int("highThreshold", ppCfg.HighThreshold),
			zap.Int("mediumThreshold", ppCfg.MediumThreshold))
	}
	tpCfg := normalizeTrafficPolicy(config.Traffic.Policy)
	if tpCfg.Enabled {
		rawRs = withTrafficPolicyRules(rawRs, tpCfg)
		logger.Info("traffic classification policy enabled")
	}
	rsConfig := &ruleset.BuiltinConfig{
		Logger:               &rulesetLogger{},
		GeoSiteFilename:      config.Ruleset.GeoSite,
		GeoIpFilename:        config.Ruleset.GeoIp,
		ProtectedDialContext: engineConfig.IO.ProtectedDialContext,
	}
	rs, err := ruleset.CompileExprRules(rawRs, analyzers, modifiers, rsConfig)
	if err != nil {
		logger.Fatal("failed to compile rules", zap.Error(err))
	}
	engineConfig.Ruleset = rs

	// Engine
	en, err := engine.NewEngine(*engineConfig)
	if err != nil {
		logger.Fatal("failed to initialize engine", zap.Error(err))
	}

	// Signal handling
	ctx, cancelFunc := context.WithCancel(context.Background())
	go func() {
		// Graceful shutdown
		shutdownChan := make(chan os.Signal, 1)
		signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
		<-shutdownChan
		logger.Info("shutting down gracefully...")
		cancelFunc()
	}()
	go func() {
		// Rule, proxy feature & traffic feature reload
		reloadChan := make(chan os.Signal, 1)
		signal.Notify(reloadChan, syscall.SIGHUP)
		for {
			<-reloadChan
			logger.Info("reloading rules, proxy features and traffic features")
			if proxyAnalyzer.HasFeatureFile() {
				if err := proxyAnalyzer.ReloadFeatures(); err != nil {
					logger.Error("failed to reload proxy features, using old features", zap.Error(err))
				} else {
					logger.Info("proxy features reloaded")
				}
			}
			if trafficAnalyzer.HasFeatureFile() {
				if err := trafficAnalyzer.ReloadFeatures(); err != nil {
					logger.Error("failed to reload traffic features, using old features", zap.Error(err))
				} else {
					logger.Info("traffic features reloaded")
				}
			}
			rawRs, err := ruleset.ExprRulesFromYAML(args[0])
			if err != nil {
				logger.Error("failed to load rules, using old rules", zap.Error(err))
				continue
			}
			if ppCfg.Enabled {
				rawRs = withProxyPolicyRules(rawRs, ppCfg)
			}
			if tpCfg.Enabled {
				rawRs = withTrafficPolicyRules(rawRs, tpCfg)
			}
			rs, err := ruleset.CompileExprRules(rawRs, analyzers, modifiers, rsConfig)
			if err != nil {
				logger.Error("failed to compile rules, using old rules", zap.Error(err))
				continue
			}
			err = en.UpdateRuleset(rs)
			if err != nil {
				logger.Error("failed to update ruleset", zap.Error(err))
			} else {
				logger.Info("rules reloaded")
			}
		}
	}()

	logger.Info("engine started")
	logger.Info("engine exited", zap.Error(en.Run(ctx)))
}

type engineLogger struct{}

func (l *engineLogger) WorkerStart(id int) {
	logger.Debug("worker started", zap.Int("id", id))
}

func (l *engineLogger) WorkerStop(id int) {
	logger.Debug("worker stopped", zap.Int("id", id))
}

func (l *engineLogger) TCPStreamNew(workerID int, info ruleset.StreamInfo) {
	logger.Debug("new TCP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
}

func (l *engineLogger) TCPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	logger.Debug("TCP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
}

func (l *engineLogger) TCPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	logger.Info("TCP stream action",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.String("action", action.String()),
		zap.Bool("noMatch", noMatch))
}

func (l *engineLogger) UDPStreamNew(workerID int, info ruleset.StreamInfo) {
	logger.Debug("new UDP stream",
		zap.Int("workerID", workerID),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()))
}

func (l *engineLogger) UDPStreamPropUpdate(info ruleset.StreamInfo, close bool) {
	logger.Debug("UDP stream property update",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Any("props", info.Props),
		zap.Bool("close", close))
}

func (l *engineLogger) UDPStreamAction(info ruleset.StreamInfo, action ruleset.Action, noMatch bool) {
	logger.Info("UDP stream action",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.String("action", action.String()),
		zap.Bool("noMatch", noMatch))
}

func (l *engineLogger) ModifyError(info ruleset.StreamInfo, err error) {
	logger.Error("modify error",
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
}

func (l *engineLogger) AnalyzerDebugf(streamID int64, name string, format string, args ...interface{}) {
	logger.Debug("analyzer debug message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *engineLogger) AnalyzerInfof(streamID int64, name string, format string, args ...interface{}) {
	logger.Info("analyzer info message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

func (l *engineLogger) AnalyzerErrorf(streamID int64, name string, format string, args ...interface{}) {
	logger.Error("analyzer error message",
		zap.Int64("id", streamID),
		zap.String("name", name),
		zap.String("msg", fmt.Sprintf(format, args...)))
}

type rulesetLogger struct{}

func (l *rulesetLogger) Log(info ruleset.StreamInfo, name string) {
	score, level := proxySensitivity(info)
	switch {
	case strings.HasPrefix(name, "proxy_policy_block_"):
		logger.Warn("proxy high-similarity blocked",
			zap.String("name", name),
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.Any("sensitivity_score", score),
			zap.Any("sensitivity_level", level),
			zap.Any("props", info.Props))
	case strings.HasPrefix(name, "proxy_policy_warn_"):
		logger.Warn("proxy similarity warning",
			zap.String("name", name),
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.Any("sensitivity_score", score),
			zap.Any("sensitivity_level", level),
			zap.Any("props", info.Props))
	default:
		logger.Info("ruleset log",
			zap.String("name", name),
			zap.Int64("id", info.ID),
			zap.String("src", info.SrcString()),
			zap.String("dst", info.DstString()),
			zap.Any("props", info.Props))
	}
}

func (l *rulesetLogger) MatchError(info ruleset.StreamInfo, name string, err error) {
	logger.Error("ruleset match error",
		zap.String("name", name),
		zap.Int64("id", info.ID),
		zap.String("src", info.SrcString()),
		zap.String("dst", info.DstString()),
		zap.Error(err))
}

func envOrDefaultString(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func normalizeProxyPolicy(in cliConfigProxyPolicy) proxyPolicyConfig {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	high := in.HighThreshold
	if high <= 0 || high > 100 {
		high = 85
	}
	medium := in.MediumThreshold
	if medium <= 0 || medium >= high {
		medium = 70
		if medium >= high {
			medium = high - 1
		}
		if medium <= 0 {
			medium = 1
		}
	}
	return proxyPolicyConfig{
		Enabled:         enabled,
		HighThreshold:   high,
		MediumThreshold: medium,
	}
}

func withProxyPolicyRules(raw []ruleset.ExprRule, cfg proxyPolicyConfig) []ruleset.ExprRule {
	rules := []ruleset.ExprRule{
		{
			Name:   "proxy_policy_block_source_penalty",
			Action: "block",
			Log:    true,
			Expr:   `proxy != nil && proxy.protocol == "source_ip_penalty"`,
		},
		{
			Name:   "proxy_policy_block_high",
			Action: "block",
			Log:    true,
			Expr:   fmt.Sprintf(`proxy != nil && proxy.sensitivity_score >= %d`, cfg.HighThreshold),
		},
		{
			Name: "proxy_policy_warn_medium",
			Log:  true,
			Expr: fmt.Sprintf(`proxy != nil && proxy.sensitivity_score >= %d && proxy.sensitivity_score < %d`,
				cfg.MediumThreshold, cfg.HighThreshold),
		},
		{
			Name: "proxy_policy_warn_low",
			Log:  true,
			Expr: fmt.Sprintf(`proxy != nil && proxy.sensitivity_score > 0 && proxy.sensitivity_score < %d`,
				cfg.MediumThreshold),
		},
	}
	out := make([]ruleset.ExprRule, 0, len(rules)+len(raw))
	out = append(out, rules...)
	out = append(out, raw...)
	return out
}

func normalizeTrafficPolicy(in cliConfigTrafficPolicy) trafficPolicyConfig {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	return trafficPolicyConfig{Enabled: enabled}
}

func withTrafficPolicyRules(raw []ruleset.ExprRule, cfg trafficPolicyConfig) []ruleset.ExprRule {
	if !cfg.Enabled {
		return raw
	}
	rules := []ruleset.ExprRule{
		{
			Name: "traffic_classification_log",
			Log:  true,
			Expr: `traffic != nil`,
		},
	}
	out := make([]ruleset.ExprRule, 0, len(rules)+len(raw))
	out = append(out, rules...)
	out = append(out, raw...)
	return out
}

func proxySensitivity(info ruleset.StreamInfo) (score interface{}, level interface{}) {
	if p, ok := info.Props["proxy"]; ok && p != nil {
		return p["sensitivity_score"], p["sensitivity_level"]
	}
	return nil, nil
}
