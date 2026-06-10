# quic-prober

模拟 GFW 主动探测行为的 QUIC 代理服务器检测工具。

向目标服务器和参考真实 QUIC 服务器分别发送结构化探测包，对比两者行为差异，找出可能暴露代理身份的特征。

```
quic-prober ──── 探测 ────→ 目标服务器（Hysteria2 / TUIC 等）
             ──── 探测 ────→ 参考服务器（cloudflare.com）
             ←─── 对比 · 评分 · 生成报告 ──────────────────
```

> [English](README.md)


## 探测项目

| 探测类型 | 检测内容 |
|---------|---------|
| `http3` | 完整 HTTP/3 GET 请求 — 状态码、响应头、响应时间 |
| `tls` | 仅 TLS 握手 — ALPN、密码套件、证书链、ECH 支持 |
| `replay` | 重放 QUIC Initial 包 — 重放保护机制 |
| `null` | 完成握手后不开流 — 空闲行为与关闭码 |
| `random` | 11 种大小随机 UDP（1–1500 字节）— 垃圾包响应 |
| `malformed` | 5 种畸形 QUIC Initial — 错误处理一致性 |

## 安装

```bash
go install github.com/HaizakiKu/quic-prober@latest
```

或从源码构建：

```bash
git clone https://github.com/HaizakiKu/quic-prober
cd quic-prober
go build -o quic-prober .
```

**依赖：** Go 1.24+

## 使用方法

```bash
# 基础扫描
quic-prober --target your-server.com:443

# 多参考服务器，多数票共识
quic-prober --target your-server.com:443 \
            --reference cloudflare.com:443,google.com:443 \
            --reference-mode majority

# 只运行指定探测项
quic-prober --target your-server.com:443 --probes http3,tls

# JSON 输出
quic-prober --target your-server.com:443 --json | jq .

# 显示每个参考服务器的原始结果
quic-prober --target your-server.com:443 --verbose
```

### 参数说明

```
--target           host:port   目标服务器（必填）
--reference        host:port   参考服务器，逗号分隔（默认：cloudflare.com:443）
--reference-mode   string      多参考服务器结果合并方式（默认：any）
                                 any      任意参考服务器出现该行为即视为正常
                                 majority 超过半数参考服务器出现才视为正常
                                 all      全部参考服务器出现才视为正常
--probes           string      探测项列表，逗号分隔（默认：all）
                                 http3, tls, replay, null, random, malformed
--random-sizes     string      随机探测的包大小
                               （默认：1,8,16,32,64,128,256,512,1024,1400,1500）
--timeout          int         单项探测超时，秒（默认：10）
--probe-interval   int         探测间隔，毫秒（默认：2000）
--verbose          bool        输出每个参考服务器的原始结果
--json             bool        以 JSON 格式输出结果到 stdout
```

探测开始前会通过快速 QUIC 握手检测目标是否可达，DNS 失败或在 `--timeout` 秒内无响应时立即中止。

## 输出示例

```
quic-prober v0.1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target:    your-server.com:443
Reference: cloudflare.com:443
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[✅ PASS] TLS Handshake
  ALPN h3 ✓, cipher 0x1301 ✓, cert: CN=your-server.com

[⚠️  WARN] HTTP/3 GET /
  Status 200 OK ✓
  Missing "Server" header → configure masquerade reverse proxy to add Server header

[✅ PASS] Replay probe
  Both servers: no-response ✓

[✅ PASS] Null connection
  No unprompted streams, idle timeout matches reference ✓

[✅ PASS] Random UDP (11 sizes, 1–1500 bytes)
  No response to random UDP ✓

[✅ PASS] Malformed QUIC Initial (5 variants)
  All malformed variants: no application data returned ✓

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Overall: ⚠️  LOW-MEDIUM RISK
  5 passed, 1 warning(s).
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 全部通过 |
| `1` | 存在警告 |
| `2` | 存在失败 |

## 评分逻辑

每项探测将目标服务器行为与合并后的参考结果对比：

- **FAIL** — 目标行为与真实 QUIC 服务器不符，可被 GFW 主动探测识别
- **WARN** — 目标行为与参考存在可疑差异，建议关注
- **PASS** — 在该探测项上，目标与真实 QUIC 服务器行为一致

常见问题及修复方向：

| 探测项 | 问题 | 修复建议 |
|--------|------|---------|
| `http3` | 状态码不是 200 | 配置伪装 Web 服务 |
| `http3` | 缺少 `Server` 响应头 | 在反代配置中添加 Server 头 |
| `tls` | ALPN 不是 `h3` | 服务端启用 QUIC/HTTP3 |
| `tls` | 自签名证书 | 使用 CA 签发的证书 |
| `replay` | 接受重放的 Initial 包 | 确认 QUIC 实现启用重放保护 |
| `null` | 主动推送 HTTP/3 流 | 禁用未经请求的服务端推流 |
| `random` | 响应随机 UDP 包 | 检查防火墙配置或 QUIC 实现 |

## 技术栈

- **QUIC / HTTP3** — [`quic-go`](https://github.com/quic-go/quic-go)
- **TLS** — Go 标准库 `crypto/tls`
- **原始 UDP** — Go 标准库 `net`
- **QUIC Initial 包** — 完全按 RFC 9001 从零构建（AES-128-GCM + 包头保护）

## 免责声明

本工具**仅限授权测试**。请只对你拥有或已获得明确授权的服务器使用。部分畸形包探测可能触发未修复服务端实现的异常行为。对于任何未经授权或不当使用造成的损失，作者概不负责。
