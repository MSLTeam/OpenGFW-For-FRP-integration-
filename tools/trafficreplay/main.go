package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/apernet/OpenGFW/analyzer"
	"github.com/apernet/OpenGFW/analyzer/traffic"
)

type expected struct {
	Label         string `json:"label"`
	Family        string `json:"family"`
	Method        string `json:"method"`
	MinConfidence int    `json:"min_confidence"`
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
	label      string
	family     string
	method     string
	confidence int
}

func main() {
	dataset := flag.String("dataset", "testdata/traffic-classification-sim.jsonl", "JSONL dataset path")
	featureFile := flag.String("features", "", "traffic feature config file (optional)")
	verbose := flag.Bool("verbose", false, "print per-record classification result")
	minAccuracy := flag.Float64("min-accuracy", -1, "minimum acceptable accuracy, e.g. 0.95; <0 disables threshold check")
	flag.Parse()

	ta := traffic.NewTrafficAnalyzer()
	if err := ta.SetFeatureFile(*featureFile); err != nil {
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

	total := 0
	pass := 0
	failures := make([]string, 0)
	for _, rec := range records {
		r, err := replayOne(ta, rec)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: 回放失败: %v", rec.Name, err))
			continue
		}
		total++
		if *verbose {
			fmt.Printf("[样本] %-34s family=%-16s label=%-30s method=%-18s confidence=%d\n",
				rec.Name, fallbackDash(r.family), fallbackDash(r.label), fallbackDash(r.method), r.confidence)
		}
		ok := compareExpected(rec.Expected, r)
		if ok {
			pass++
		} else {
			failures = append(failures, fmt.Sprintf(
				"%s: 期望{family=%q label=%q method=%q min_conf=%d} 实际{family=%q label=%q method=%q conf=%d}",
				rec.Name, rec.Expected.Family, rec.Expected.Label, rec.Expected.Method, rec.Expected.MinConfidence,
				r.family, r.label, r.method, r.confidence,
			))
		}
	}

	if total == 0 {
		fmt.Fprintln(os.Stderr, "无有效样本")
		os.Exit(1)
	}
	accuracy := float64(pass) / float64(total)
	fmt.Printf("样本总数: %d 通过: %d 失败: %d\n", total, pass, total-pass)
	fmt.Printf("分类准确率: %.4f\n", accuracy)

	failed := false
	if *minAccuracy >= 0 && accuracy < *minAccuracy {
		failed = true
		fmt.Printf("阈值校验失败: accuracy=%.6f < min-accuracy=%.6f\n", accuracy, *minAccuracy)
	}
	if len(failures) > 0 {
		failed = true
		fmt.Println("失败样本:")
		for _, f := range failures {
			fmt.Printf("- %s\n", f)
		}
	}
	if failed {
		os.Exit(2)
	}
	fmt.Println("流量分类回放通过")
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

func replayOne(ta *traffic.TrafficAnalyzer, rec record) (result, error) {
	switch rec.Transport {
	case "tcp":
		return replayTCP(ta, rec)
	case "udp":
		return replayUDP(ta, rec)
	default:
		return result{}, fmt.Errorf("未知 transport: %q", rec.Transport)
	}
}

func replayTCP(ta *traffic.TrafficAnalyzer, rec record) (result, error) {
	info, err := tcpInfoFromRecord(rec)
	if err != nil {
		return result{}, err
	}
	stream := ta.NewTCP(info, nil)
	var last *analyzer.PropUpdate
	if len(rec.Segments) == 0 {
		return result{}, fmt.Errorf("tcp 样本缺少 segments")
	}
	streamDone := false
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
			streamDone = true
			break
		}
	}
	if !streamDone {
		if u := stream.Close(false); u != nil {
			last = u
		}
	}
	return propToResult(last), nil
}

func replayUDP(ta *traffic.TrafficAnalyzer, rec record) (result, error) {
	info, err := udpInfoFromRecord(rec)
	if err != nil {
		return result{}, err
	}
	stream := ta.NewUDP(info, nil)
	var last *analyzer.PropUpdate
	if len(rec.Packets) == 0 {
		return result{}, fmt.Errorf("udp 样本缺少 packets")
	}
	streamDone := false
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
			streamDone = true
			break
		}
	}
	if !streamDone {
		if u := stream.Close(false); u != nil {
			last = u
		}
	}
	return propToResult(last), nil
}

func propToResult(u *analyzer.PropUpdate) result {
	if u == nil || u.M == nil {
		return result{}
	}
	r := result{}
	if v, ok := u.M["label"].(string); ok {
		r.label = v
	}
	if v, ok := u.M["family"].(string); ok {
		r.family = v
	}
	if v, ok := u.M["method"].(string); ok {
		r.method = v
	}
	if v, ok := toInt(u.M["confidence"]); ok {
		r.confidence = v
	}
	return r
}

func compareExpected(exp expected, got result) bool {
	if exp.Label != "" && got.label != exp.Label {
		return false
	}
	if exp.Family != "" && got.family != exp.Family {
		return false
	}
	if exp.Method != "" && got.method != exp.Method {
		return false
	}
	if exp.MinConfidence > 0 && got.confidence < exp.MinConfidence {
		return false
	}
	return true
}

func fallbackDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
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
