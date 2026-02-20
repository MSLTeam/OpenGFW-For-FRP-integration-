# Proxy 特征库持续更新流程

## 1. 运行时配置

在 `config.yaml` 增加：

```yaml
proxy:
  features: /etc/opengfw/proxy-features.yaml
  policy:
    enabled: true
    highThreshold: 85
    mediumThreshold: 70
```

`proxy.features` 指向外置特征库文件。发送 `SIGHUP` 后会同时重载规则和特征库。
`proxy.policy` 默认启用：高相似度立即阻断，中低相似度仅告警。

## 2. 特征库格式

参考：`docs/proxy-features.example.yaml`

关键字段：
- `grayPercent`: 灰度比例（1-100）
- `sourcePenalty*`: 源 IP 跨连接封禁参数（TTL、触发阈值、封禁分值、容量）
- `tcpEntropyThreshold` / `udpEntropyThreshold`
- `tls.*Keywords` / `tls.commonALPN`

## 3. 回放评估

基准样本：`testdata/proxy-benchmark.jsonl`

```bash
go run ./tools/proxyreplay -dataset testdata/proxy-benchmark.jsonl -features /etc/opengfw/proxy-features.yaml
```

## 4. 阈值守护与自动回滚

```bash
go run ./tools/proxyreplay \
  -dataset testdata/proxy-benchmark.jsonl \
  -features /etc/opengfw/proxy-features.yaml \
  -max-fpr 0.005 \
  -rollback-file /etc/opengfw/proxy-features.prev.yaml
```

当回放失败或 `FPR` 超阈值时，工具会自动把 `rollback-file` 覆盖回 `features`。
