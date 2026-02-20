package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/proxy"
)

type expected struct {
	IsProxy        bool   `json:"is_proxy"`
	Protocol       string `json:"protocol"`
	MinSensitivity int    `json:"min_sensitivity"`
	Action         string `json:"action"` // allow / warn / block
}

type record struct {
	Name      string   `json:"name"`
	Transport string   `json:"transport"` // tcp / udp
	SrcIP     string   `json:"src_ip"`
	DstIP     string   `json:"dst_ip"`
	SrcPort   uint16   `json:"src_port"`
	DstPort   uint16   `json:"dst_port"`
	Segments  []string `json:"segments"` // TCP payload specs
	Packets   []string `json:"packets"`  // UDP payload specs
	Expected  expected `json:"expected"`
}

type result struct {
	isProxy     bool
	protocol    string
	sensitivity int
	action      string
}

type policyThresholds struct {
	high   int
	medium int
}

type metrics struct {
	total int
	tp    int
	fp    int
	tn    int
	fn    int

	protoTotal int
	protoOK    int

	actionTotal int
	actionOK    int

	blockCount int
	warnCount  int
	allowCount int
}

func main() {
	dataset := flag.String("dataset", "testdata/proxy-benchmark.jsonl", "JSONL dataset path")
	featureFile := flag.String("features", "", "proxy feature config file (optional)")
	maxFPR := flag.Float64("max-fpr", -1, "maximum acceptable FPR, e.g. 0.005; <0 disables threshold check")
	rollbackFile := flag.String("rollback-file", "", "fallback feature file used when threshold check fails")
	highThreshold := flag.Int("high-threshold", 85, "high similarity threshold for block action")
	mediumThreshold := flag.Int("medium-threshold", 70, "medium similarity threshold for warn action")
	verbose := flag.Bool("verbose", false, "print per-record protocol/score/action")
	flag.Parse()
	policy := normalizePolicyThresholds(*highThreshold, *mediumThreshold)

	pa := proxy.NewProxyAnalyzer()
	if err := pa.SetFeatureFile(*featureFile); err != nil {
		fmt.Fprintf(os.Stderr, "加载特征库失败: %v\n", err)
		os.Exit(1)
	}

	records, err := loadDataset(*dataset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载数据集失败: %v\n", err)
		os.Exit(1)
	}
	if len(records) == 0 {
		fmt.Fprintln(os.Stderr, "数据集为空")
		os.Exit(1)
	}

	var m metrics
	failures := make([]string, 0)
	for _, rec := range records {
		r, err := replayOne(pa, rec)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: 回放失败: %v", rec.Name, err))
			continue
		}
		r.action = decideAction(r, policy)
		if *verbose {
			printRecordResult(rec, r)
		}
		ok := updateMetrics(&m, rec.Expected, r)
		if !ok {
			failures = append(failures, fmt.Sprintf(
				"%s: 期望{proxy=%v protocol=%q min=%d action=%q} 实际{proxy=%v protocol=%q score=%d action=%q}",
				rec.Name, rec.Expected.IsProxy, rec.Expected.Protocol, rec.Expected.MinSensitivity, rec.Expected.Action,
				r.isProxy, r.protocol, r.sensitivity, r.action,
			))
		}
	}

	precision, recall, fpr := calcPRF(m)
	fmt.Printf("样本总数: %d\n", m.total)
	fmt.Printf("TP=%d FP=%d TN=%d FN=%d\n", m.tp, m.fp, m.tn, m.fn)
	fmt.Printf("Precision=%.4f Recall=%.4f FPR=%.4f\n", precision, recall, fpr)
	fmt.Printf("策略阈值: high=%d medium=%d\n", policy.high, policy.medium)
	fmt.Printf("动作统计: block=%d warn=%d allow=%d\n", m.blockCount, m.warnCount, m.allowCount)
	if m.protoTotal > 0 {
		fmt.Printf("协议命中率=%.4f (%d/%d)\n", float64(m.protoOK)/float64(m.protoTotal), m.protoOK, m.protoTotal)
	}
	if m.actionTotal > 0 {
		fmt.Printf("动作命中率=%.4f (%d/%d)\n", float64(m.actionOK)/float64(m.actionTotal), m.actionOK, m.actionTotal)
	}

	thresholdFailed := false
	if *maxFPR >= 0 && fpr > *maxFPR {
		thresholdFailed = true
		fmt.Printf("阈值校验失败: FPR=%.6f > max-fpr=%.6f\n", fpr, *maxFPR)
	}

	if len(failures) > 0 {
		fmt.Println("失败样本:")
		for _, f := range failures {
			fmt.Printf("- %s\n", f)
		}
		thresholdFailed = true
	}
	if thresholdFailed {
		if strings.TrimSpace(*featureFile) != "" && strings.TrimSpace(*rollbackFile) != "" {
			if err := copyFile(*rollbackFile, *featureFile); err != nil {
				fmt.Fprintf(os.Stderr, "自动回滚失败: %v\n", err)
			} else {
				fmt.Printf("已自动回滚特征库: %s <- %s\n", *featureFile, *rollbackFile)
			}
		}
		os.Exit(2)
	}
	fmt.Println("回放评估通过")
}

func loadDataset(path string) ([]record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := make([]record, 0)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		r.Transport = strings.ToLower(strings.TrimSpace(r.Transport))
		out = append(out, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func replayOne(pa *proxy.ProxyAnalyzer, rec record) (result, error) {
	switch rec.Transport {
	case "tcp":
		return replayTCP(pa, rec)
	case "udp":
		return replayUDP(pa, rec)
	default:
		return result{}, fmt.Errorf("未知 transport: %q", rec.Transport)
	}
}

func replayTCP(pa *proxy.ProxyAnalyzer, rec record) (result, error) {
	info, err := tcpInfoFromRecord(rec)
	if err != nil {
		return result{}, err
	}
	stream := pa.NewTCP(info, nil)
	var last *analyzer.PropUpdate
	if len(rec.Segments) == 0 {
		return result{}, fmt.Errorf("tcp 样本缺少 segments")
	}
	for i, s := range rec.Segments {
		bs, err := decodeSpec(s)
		if err != nil {
			return result{}, err
		}
		u, done := stream.Feed(false, i == 0, i == len(rec.Segments)-1, 0, bs)
		if u != nil {
			last = u
		}
		if done {
			break
		}
	}
	return propToResult(last), nil
}

func replayUDP(pa *proxy.ProxyAnalyzer, rec record) (result, error) {
	info, err := udpInfoFromRecord(rec)
	if err != nil {
		return result{}, err
	}
	stream := pa.NewUDP(info, nil)
	var last *analyzer.PropUpdate
	if len(rec.Packets) == 0 {
		return result{}, fmt.Errorf("udp 样本缺少 packets")
	}
	for _, s := range rec.Packets {
		bs, err := decodeSpec(s)
		if err != nil {
			return result{}, err
		}
		u, done := stream.Feed(false, bs)
		if u != nil {
			last = u
		}
		if done {
			break
		}
	}
	return propToResult(last), nil
}

func propToResult(u *analyzer.PropUpdate) result {
	if u == nil || u.M == nil {
		return result{}
	}
	r := result{isProxy: true}
	if p, ok := u.M["protocol"].(string); ok {
		r.protocol = p
	}
	if s, ok := toInt(u.M["sensitivity_score"]); ok {
		r.sensitivity = s
	}
	return r
}

func updateMetrics(m *metrics, exp expected, got result) bool {
	m.total++
	switch got.action {
	case "block":
		m.blockCount++
	case "warn":
		m.warnCount++
	default:
		m.allowCount++
	}

	if exp.IsProxy && got.isProxy {
		m.tp++
	} else if !exp.IsProxy && got.isProxy {
		m.fp++
	} else if !exp.IsProxy && !got.isProxy {
		m.tn++
	} else {
		m.fn++
	}

	ok := (exp.IsProxy == got.isProxy)
	if exp.Protocol != "" && exp.IsProxy {
		m.protoTotal++
		if got.protocol == exp.Protocol {
			m.protoOK++
		} else {
			ok = false
		}
	}
	if exp.MinSensitivity > 0 && got.sensitivity < exp.MinSensitivity {
		ok = false
	}
	expAction := normalizeAction(exp.Action)
	if expAction != "" {
		m.actionTotal++
		if got.action == expAction {
			m.actionOK++
		} else {
			ok = false
		}
	}
	return ok
}

func calcPRF(m metrics) (precision, recall, fpr float64) {
	if m.tp+m.fp > 0 {
		precision = float64(m.tp) / float64(m.tp+m.fp)
	}
	if m.tp+m.fn > 0 {
		recall = float64(m.tp) / float64(m.tp+m.fn)
	}
	if m.fp+m.tn > 0 {
		fpr = float64(m.fp) / float64(m.fp+m.tn)
	}
	return
}

func decodeSpec(spec string) ([]byte, error) {
	if strings.HasPrefix(spec, "ascii:") {
		return []byte(strings.TrimPrefix(spec, "ascii:")), nil
	}
	spec = strings.TrimSpace(spec)
	if strings.Contains(spec, "+") {
		parts := strings.Split(spec, "+")
		out := make([]byte, 0)
		for _, p := range parts {
			bs, err := decodeSpec(p)
			if err != nil {
				return nil, err
			}
			out = append(out, bs...)
		}
		return out, nil
	}
	switch {
	case strings.HasPrefix(spec, "hex:"):
		hexPart := strings.TrimSpace(strings.TrimPrefix(spec, "hex:"))
		hexPart = strings.ReplaceAll(hexPart, " ", "")
		return hex.DecodeString(hexPart)
	case strings.HasPrefix(spec, "gen:zeros:"):
		nStr := strings.TrimPrefix(spec, "gen:zeros:")
		n, err := strconv.Atoi(strings.TrimSpace(nStr))
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid zeros spec: %q", spec)
		}
		return make([]byte, n), nil
	case strings.HasPrefix(spec, "gen:range:"):
		// gen:range:80-ff[:repeat]
		body := strings.TrimPrefix(spec, "gen:range:")
		parts := strings.Split(body, ":")
		rangePart := parts[0]
		repeat := 1
		if len(parts) > 1 {
			n, err := strconv.Atoi(parts[1])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("invalid range repeat: %q", spec)
			}
			repeat = n
		}
		se := strings.Split(rangePart, "-")
		if len(se) != 2 {
			return nil, fmt.Errorf("invalid range spec: %q", spec)
		}
		start, err := strconv.ParseUint(se[0], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid range start: %q", spec)
		}
		end, err := strconv.ParseUint(se[1], 16, 8)
		if err != nil || end < start {
			return nil, fmt.Errorf("invalid range end: %q", spec)
		}
		chunkLen := int(end-start) + 1
		out := make([]byte, 0, chunkLen*repeat)
		for r := 0; r < repeat; r++ {
			for v := start; v <= end; v++ {
				out = append(out, byte(v))
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown payload spec: %q", spec)
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

func normalizePolicyThresholds(high, medium int) policyThresholds {
	if high <= 0 || high > 100 {
		high = 85
	}
	if medium <= 0 || medium >= high {
		medium = 70
		if medium >= high {
			medium = high - 1
		}
		if medium <= 0 {
			medium = 1
		}
	}
	return policyThresholds{high: high, medium: medium}
}

func decideAction(r result, p policyThresholds) string {
	if !r.isProxy {
		return "allow"
	}
	if r.protocol == "source_ip_penalty" {
		return "block"
	}
	if r.sensitivity >= p.high {
		return "block"
	}
	if r.sensitivity >= p.medium {
		return "warn"
	}
	if r.sensitivity > 0 {
		return "warn"
	}
	return "allow"
}

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "warn", "block":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return ""
	}
}

func printRecordResult(rec record, r result) {
	proto := r.protocol
	if proto == "" {
		proto = "-"
	}
	fmt.Printf("[样本] %-30s src=%-15s proto=%-24s score=%3d action=%s\n",
		rec.Name, srcLabel(rec), proto, r.sensitivity, r.action)
}

func srcLabel(rec record) string {
	s := strings.TrimSpace(rec.SrcIP)
	if s == "" {
		return "-"
	}
	return s
}

func tcpInfoFromRecord(rec record) (analyzer.TCPInfo, error) {
	srcIP, err := parseIP("src_ip", rec.SrcIP)
	if err != nil {
		return analyzer.TCPInfo{}, err
	}
	dstIP, err := parseIP("dst_ip", rec.DstIP)
	if err != nil {
		return analyzer.TCPInfo{}, err
	}
	return analyzer.TCPInfo{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: rec.SrcPort,
		DstPort: rec.DstPort,
	}, nil
}

func udpInfoFromRecord(rec record) (analyzer.UDPInfo, error) {
	srcIP, err := parseIP("src_ip", rec.SrcIP)
	if err != nil {
		return analyzer.UDPInfo{}, err
	}
	dstIP, err := parseIP("dst_ip", rec.DstIP)
	if err != nil {
		return analyzer.UDPInfo{}, err
	}
	return analyzer.UDPInfo{
		SrcIP:   srcIP,
		DstIP:   dstIP,
		SrcPort: rec.SrcPort,
		DstPort: rec.DstPort,
	}, nil
}

func parseIP(field, value string) (net.IP, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("非法 %s: %q", field, value)
	}
	return ip, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
