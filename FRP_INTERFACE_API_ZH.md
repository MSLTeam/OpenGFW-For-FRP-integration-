# OpenGFW FRP 接口调用文档（中文）

本文档整理当前项目中为 FRP 对接提供的全部可调用接口，重点覆盖 `integration/frp` 包的初始化、流式喂包、策略控制、会话管理与结果解释。

适用场景：

- 在 FRP 数据通道中实时识别代理流量与业务流量。
- 对高风险流量即时阻断，对中低风险流量告警。
- 对 TCP 上 HTTP/HTTPS 按策略执行统一阻断。
- 输出统一分类标签（Minecraft、代理类、服务类等）。

---

## 1. 包路径与核心对象

Go 包路径：

```go
import frpint "github.com/apernet/OpenGFW/integration/frp"
```

核心对象：

- `Config`：初始化参数（特征文件 + 策略）
- `Engine`：分析引擎（创建流、热重载、策略更新）
- `TCPStream` / `UDPStream`：逐连接流式分析对象
- `SessionManager`：按 `sessionID` 自动管理流对象生命周期
- `InspectionReport`：统一输出（动作 + 原因 + 代理检测 + 流量分类）

---

## 2. 初始化接口

### 2.1 `DefaultConfig() Config`

返回默认配置，当前默认值：

- `ProxyPolicy.Enabled = true`
- `ProxyPolicy.HighThreshold = 85`
- `ProxyPolicy.MediumThreshold = 70`
- `TrafficPolicy.Enabled = true`
- `TrafficPolicy.BlockWebTCP = true`

### 2.2 `Config` 字段

```go
type Config struct {
    ProxyFeatureFile   string
    TrafficFeatureFile string
    ProxyPolicy        ProxyPolicy
    TrafficPolicy      TrafficPolicy
}
```

字段说明：

- `ProxyFeatureFile`：代理识别特征文件（YAML）
- `TrafficFeatureFile`：业务流量分类特征文件（YAML）
- `ProxyPolicy`：代理相似度决策阈值
- `TrafficPolicy`：流量策略（当前包含 TCP Web 阻断）

### 2.3 `NewEngine(cfg Config) (*Engine, error)`

功能：

- 加载代理/流量特征文件
- 归一化策略参数
- 返回可复用的引擎实例

示例：

```go
cfg := frpint.DefaultConfig()
cfg.ProxyFeatureFile = "/etc/opengfw/proxy-features.yaml"
cfg.TrafficFeatureFile = "/etc/opengfw/traffic-features.yaml"

engine, err := frpint.NewEngine(cfg)
if err != nil {
    panic(err)
}
```

---

## 3. 策略接口

### 3.1 `ProxyPolicy`

```go
type ProxyPolicy struct {
    Enabled         bool
    HighThreshold   int
    MediumThreshold int
}
```

决策规则：

- `source_ip_penalty`：直接 `block`
- `sensitivity_score >= HighThreshold`：`block`
- `MediumThreshold <= score < HighThreshold`：`warn`
- `0 < score < MediumThreshold`：`warn`
- 其他：`allow`

接口：

- `SetProxyPolicy(policy ProxyPolicy)`

注意：

- `SetProxyPolicy(ProxyPolicy{})` 会导致 `Enabled=false`（即关闭代理策略）；阈值会归一化为默认值。

### 3.2 `TrafficPolicy`

```go
type TrafficPolicy struct {
    Enabled     bool
    BlockWebTCP bool
}
```

当前规则：

- 当 `Enabled=true && BlockWebTCP=true` 时，若流量分类为
  - `Web Service (HTTP)` 且 `transport=tcp`，或
  - `Web Service (HTTPS/TLS)` 且 `transport=tcp`
  则动作为 `block`。

接口：

- `SetTrafficPolicy(policy TrafficPolicy)`

注意：

- `SetTrafficPolicy(TrafficPolicy{})` 会关闭该策略（`Enabled=false`）。

### 3.3 动作优先级

最终动作优先级（高到低）：

1. 源 IP 惩罚命中（`source_ip_penalty`）=> `block`
2. TCP Web 阻断策略命中 => `block`
3. 代理相似度策略判定 => `block/warn/allow`

---

## 4. 元信息与流对象接口

### 4.1 `StreamMeta`

```go
type StreamMeta struct {
    SrcIP   net.IP
    DstIP   net.IP
    SrcPort uint16
    DstPort uint16
}
```

约束：

- `SrcIP` 不能为空
- `DstIP` 不能为空

否则创建流时返回错误。

### 4.2 创建流

- `NewTCPStream(meta StreamMeta) (*TCPStream, error)`
- `NewUDPStream(meta StreamMeta) (*UDPStream, error)`

说明：

- 流对象会同时驱动 `proxy` 与 `traffic` 两个分析器。
- 流对象内部保存了创建时的策略快照；后续调用 `SetProxyPolicy/SetTrafficPolicy` 仅影响新建流。

---

## 5. TCP/UDP 喂包接口

### 5.1 TCP

```go
func (s *TCPStream) Feed(rev, start, end bool, skip int, data []byte) InspectionReport
func (s *TCPStream) Close(limited bool) InspectionReport
```

参数说明：

- `rev`：是否为反向方向数据
- `start`：是否为该方向起始片段
- `end`：是否为该方向结束片段
- `skip`：中间被跳过的字节数（非 0 会影响分析完整性）
- `data`：当前载荷
- `limited`：关闭时是否为受限关闭（透传到底层分析器）

推荐调用时序：

1. 连接建立后创建 `TCPStream`
2. 收到每个片段调用 `Feed(...)`
3. 若 `InspectionReport.Action == block`，在 FRP 侧立即断流
4. 连接结束时调用 `Close(...)`

### 5.2 UDP

```go
func (s *UDPStream) Feed(rev bool, data []byte) InspectionReport
func (s *UDPStream) Close(limited bool) InspectionReport
```

推荐调用时序与 TCP 类似。

---

## 6. SessionManager 接口（推荐 FRP 使用）

`SessionManager` 负责按 `sessionID` 自动创建、缓存、清理流对象。

创建：

```go
mgr := frpint.NewSessionManager(engine)
```

接口：

```go
FeedTCP(sessionID string, meta StreamMeta, rev, start, end bool, skip int, data []byte) (InspectionReport, error)
CloseTCP(sessionID string, limited bool) (InspectionReport, bool)

FeedUDP(sessionID string, meta StreamMeta, rev bool, data []byte) (InspectionReport, error)
CloseUDP(sessionID string, limited bool) (InspectionReport, bool)
```

行为说明：

- `Feed*` 首次收到该 `sessionID` 时自动创建流。
- `FeedTCP` 若 `end=true` 且尚未完成，会自动补一次 `Close(false)` 并合并结果。
- 流结束后自动从内部 map 清理。
- `Close*` 的第二个返回值表示该 `sessionID` 是否存在。
- `sessionID` 为空会返回错误。

---

## 7. 引擎运维接口

```go
ReloadFeatures() error
SetProxyFeatureFile(path string) error
SetTrafficFeatureFile(path string) error
SetProxyPolicy(policy ProxyPolicy)
SetTrafficPolicy(policy TrafficPolicy)
```

典型热更新流程：

1. 更新特征文件路径（可选）
2. 调用 `ReloadFeatures()`
3. 如需策略变更，调用 `SetProxyPolicy` / `SetTrafficPolicy`

---

## 8. 结果结构与字段解释

### 8.1 `InspectionReport`

```go
type InspectionReport struct {
    Updated bool
    Done    bool
    Action  Action  // allow / warn / block
    Reason  string
    Proxy   *ProxyReport
    Traffic *TrafficReport
}
```

字段说明：

- `Updated`：本次调用是否拿到新分析结果
- `Done`：两个分析器是否都结束
- `Action`：当前建议动作
- `Reason`：动作原因（便于审计/日志）
- `Proxy`：代理检测详情
- `Traffic`：流量分类详情

常见 `Reason`：

- `source ip penalty`
- `traffic policy block web tcp`
- `high similarity`
- `medium similarity`
- `low similarity`
- `no similarity`
- `no proxy signal`
- `proxy policy disabled`

### 8.2 `ProxyReport`

```go
type ProxyReport struct {
    Protocol         string
    Type             string
    Class            string
    SensitivityScore int
    SensitivityLevel string
    Raw              analyzer.PropMap
}
```

### 8.3 `TrafficReport`

```go
type TrafficReport struct {
    Label      string
    Family     string
    Role       string
    Method     string
    Transport  string
    Confidence int
    Raw        analyzer.PropMap
}
```

---

## 9. FRP 接入参考代码（SessionManager 方式）

```go
package main

import (
    "net"

    frpint "github.com/apernet/OpenGFW/integration/frp"
)

func main() {
    cfg := frpint.DefaultConfig()
    cfg.ProxyFeatureFile = "/etc/opengfw/proxy-features.yaml"
    cfg.TrafficFeatureFile = "/etc/opengfw/traffic-features.yaml"

    engine, err := frpint.NewEngine(cfg)
    if err != nil {
        panic(err)
    }

    mgr := frpint.NewSessionManager(engine)

    meta := frpint.StreamMeta{
        SrcIP:   net.ParseIP("10.0.0.1"),
        DstIP:   net.ParseIP("10.0.0.2"),
        SrcPort: 50000,
        DstPort: 443,
    }

    rep, err := mgr.FeedTCP("session-1", meta, false, true, false, 0, []byte("GET / HTTP/1.1\r\nHost: a\r\n\r\n"))
    if err != nil {
        panic(err)
    }

    switch rep.Action {
    case frpint.ActionBlock:
        // FRP 侧立即断流/拒绝
    case frpint.ActionWarn:
        // FRP 侧记录告警
    case frpint.ActionAllow:
        // 正常转发
    }

    _, _ = mgr.CloseTCP("session-1", false)
}
```

---

## 10. 实施建议

- 强烈建议 FRP 侧统一使用 `SessionManager`，减少流对象管理复杂度。
- 对 `ActionBlock` 执行“立即阻断”，并记录 `Reason`、`Proxy.Raw`、`Traffic.Raw` 便于审计。
- 对 `ActionWarn` 至少落日志并打指标，后续用于阈值调优。
- 特征文件更新后调用 `ReloadFeatures()`，避免重启进程。

