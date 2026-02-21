# FRP 调用接口（Go）

为方便对接 [MSLTeam/FRP](https://github.com/MSLTeam/FRP)，新增了 `integration/frp` 包，提供统一的流式分析接口：

- 代理检测与策略动作（`allow` / `warn` / `block`）
- 流量策略动作（默认阻断 TCP 上的 HTTP/HTTPS）
- 源 IP 跨连接惩罚（由 `proxy` 分析器共享实例实现）
- 通用流量分类（Minecraft、代理类型、服务标签、自定义标签）

## 1. 初始化

```go
import (
  frpint "github.com/apernet/OpenGFW/integration/frp"
)

cfg := frpint.DefaultConfig()
cfg.ProxyFeatureFile = "/etc/opengfw/proxy-features.yaml"
cfg.TrafficFeatureFile = "/etc/opengfw/traffic-features.yaml"
// 默认已开启：TrafficPolicy.BlockWebTCP = true

engine, err := frpint.NewEngine(cfg)
if err != nil {
  panic(err)
}
```

如果 FRP 端要固定使用本仓库分支 `feat/frp-sensitive-monitoring`，请在 FRP 的 `go.mod` 增加：

```go
replace github.com/apernet/OpenGFW => github.com/MSLTeam/OpenGFW-For-FRP-integration- monitor
```

说明：当前模块名由本仓库 `go.mod` 决定为 `github.com/apernet/OpenGFW`，所以 `import` 路径仍使用 `github.com/apernet/OpenGFW/integration/frp`。

## 2. 逐连接流式调用（推荐）

```go
meta := frpint.StreamMeta{
  SrcIP:   net.ParseIP("10.0.0.1"),
  DstIP:   net.ParseIP("10.0.0.2"),
  SrcPort: 50000,
  DstPort: 1080,
}

stream, err := engine.NewTCPStream(meta)
if err != nil {
  panic(err)
}

rep := stream.Feed(false, true, false, 0, []byte{0x05, 0x01, 0x00})
// rep.Action: block / warn / allow
// rep.Proxy: 代理检测详情
// rep.Traffic: 流量分类详情
```

如果需要关闭“TCP Web 阻断”：

```go
engine.SetTrafficPolicy(frpint.TrafficPolicy{
  Enabled:     true,
  BlockWebTCP: false,
})
```

## 3. SessionManager（按 sessionID 自动管理）

```go
mgr := frpint.NewSessionManager(engine)

rep, err := mgr.FeedTCP("conn-123", meta, false, true, false, 0, payload)
if err != nil {
  // handle
}
if rep.Action == frpint.ActionBlock {
  // 在 FRP 侧执行立即阻断
}
```

## 4. 结果字段

- `InspectionReport.Action`: `allow` / `warn` / `block`
- `InspectionReport.Reason`: 动作原因
- `InspectionReport.Proxy`: 代理协议、敏感分值等
- `InspectionReport.Traffic`: 分类标签、family、method、confidence

动作优先级：

- 若命中源 IP 惩罚（`source_ip_penalty`）=> `block`
- 否则若命中流量策略（TCP 上 HTTP/HTTPS）=> `block`
- 否则按代理策略判定（高/中/低相似度）

## 5. 热重载

```go
if err := engine.ReloadFeatures(); err != nil {
  // reload failed
}
```

该调用会同时重载 `proxy` 与 `traffic` 特征文件。
