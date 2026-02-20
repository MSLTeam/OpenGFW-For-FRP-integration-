# 通用流量分类（含 Minecraft / 代理）

## 1. 配置启用

在 `config.yaml` 增加：

```yaml
traffic:
  features: /etc/opengfw/traffic-features.yaml
  policy:
    enabled: true
```

- `traffic.features`：分类特征文件路径（可热重载，`SIGHUP`）。
- `traffic.policy.enabled`：默认 `true`，会注入 `traffic != nil` 日志规则，让分类器对全部流量生效。

## 2. 特征文件

参考：`docs/traffic-features.example.yaml`

关键字段：
- `minecraft.javaServerPorts`：Java 版服务端端口（可填 MSL-FRP 对外映射端口）
- `minecraft.bedrockServerPorts`：Bedrock 版服务端端口
- `builtinPortTagEnabled`：是否启用内置常见服务端口标签
- `serviceTags`：自定义业务标签（name/family/role/transport/ports/confidence）

## 3. 分类标签说明

- `MC Server (JE)`：识别到 Java 握手且匹配服务端角色
- `MC Server (BE)`：识别到 Bedrock/RakNet 特征且匹配服务端角色
- `MC Client - Client`：识别到 Minecraft 流量但不符合服务端角色
- `Proxy (...)`：按代理协议细分（SOCKS5/HTTP CONNECT/SS-VMess-like 等）
- `VPN Tunnel (...)`：OpenVPN / WireGuard
- `Web Service (HTTP/HTTPS)`、`Remote Admin (SSH/RDP)`、`Database (...)`、`DNS Service` 等内置标签
- 你定义的 `serviceTags` 标签（用于 MSLFRP 其它穿透业务）
- `Unknown Traffic`：无法命中已知特征时的兜底分类

## 4. 规则示例

参考：`docs/traffic-classification-rules.example.yaml`

你可以直接按 `traffic.label`、`traffic.family`、`traffic.proxy.protocol` 编写日志/阻断规则。

分类器内部优先级：
1. Minecraft 特征（JE/BE）
2. 代理/VPN 指纹映射
3. 协议签名（HTTP/TLS/SSH/RDP/DNS/QUIC/STUN 等）
4. 自定义 `serviceTags` 端口标签
5. 内置端口标签
6. Unknown 兜底
