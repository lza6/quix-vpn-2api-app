# QuixVPN 2API — QuixVPN APK 逆向分析与 WireGuard 节点池工具链

> 逆向对象：**SOCKS5 v20261016 b20261016 (Premium By ElaMods)**（Telegram 流通 Mod 版）
> 真身：**QuixVPN**（`quix-vpn.com`）— WireGuard / AmneziaWG 商业 VPN，ElaMods Mod 解锁 Premium 界面
> 交付物：中文逆向报告（本 README）+ 凭据匿名收割器 + **userspace WireGuard 数据面验证器** + demo 面板（端口 8923）
> ⚠️ 本项目只做低频功能验证与学习研究，不做大规模滥用。

## 逆向核心发现

### 基本信息
| 项 | 值 |
|---|---|
| APK | `SOCKS5 v20261016 b20261016 (Premium By ElaMods).apk`（84.8 MB） |
| 真实后端 | AWS API Gateway `56rah0pl8g.execute-api.us-east-1.amazonaws.com` |
| 鉴权 | 仅静态 `x-api-key`（硬编码于客户端，匿名可用） |
| 协议 | WireGuard（`wg`）/ AmneziaWG 混淆（`awg`），UDP 41820 |
| 节点规模 | 55 个唯一节点（US/SG/IN/AU/DE/GB/NL/JP/BR/CA/FI…） |

### 凭据接口（全部已实测 ✅）
| 端点 | 方法 | 说明 |
|---|---|---|
| `getCredentialsV3` | POST | 匿名领取每节点独立 keypair + PSK，返回标准 wg-quick conf |
| `getCredentialsFallbackV3` | POST | 备用端点（实测同样 500 于坏节点） |
| `getServerListV3` | GET | 全量 69 条节点元数据（国家/分类/协议） |

请求体（全部参数已从 jadx 确认）：
```json
{"os":"a","premium_status":"f","email":"anonymous","host_name":"us.app.quix-vpn.com","country_code":"US","protocol":"wg"}
```
- `premium_status=f`（free）即可领取，无需 Firebase token
- **每台服务器独立 keypair**：同一节点多次领取返回不同 PrivateKey
- 请求头：`Content-Type: application/json` + `x-api-key: <见 fetch_quix.py>`

### 节点健康实测（2026-10-27）
- 55 唯一节点中 **10 个凭据接口返回 200**，其余 44 个后端 500（服务端真坏，重试/fallback 均无效）
- **数据面真隧道验证（wireguard-go userspace netstack，非端口探测）**：

| 节点 | 出口 IP | CF colo / loc | 稳定性（3 轮） |
|---|---|---|---|
| `us.app.quix-vpn.com` | 207.244.250.147 | ORD / US | ✅ 100%，RTT ~1.4s 最稳 |
| `in.app.quix-vpn.com` | 217.217.249.116 | BOM / IN | ✅ 100% |
| `in2.app.quix-vpn.com` | 217.217.249.116 | BOM / IN | ✅ 100% |
| `au2.app.quix-vpn.com` | 46.250.246.220 | SYD / AU | ✅ 100% |
| `sg.app.quix-vpn.com` | 82.197.70.94 | — | ⚠️ 偶发超时 |
| `app/gb/gb4` | 158.220.86.123 | — | ❌ 握手超时（服务端坏） |

### 已知限制（诚实披露）
- 这些是**数据中心 IP**，部分 AI 上游（如 notrack.ai）走隧道返回 Cloudflare 520（边缘接受、源站拒绝）——作通用代理出口可用，作 AI 上游出口需逐家实测
- 免费凭据的配额/频率上限未压测到边界（低频使用下未触发）

## 快速开始

### 1. 收割凭据
```bash
python fetch_quix.py us.app.quix-vpn.com US          # 单节点
python harvest_all.py                                 # 全量批量（仅 10 节点存活）
```

### 2. 真隧道验证（无需 TUN 驱动、无需管理员）
```bash
# Go 1.22+：wireguard-go userspace netstack，隧道内拉 api.ipify.org 验证出口
go build -o quixwg.exe .
./quixwg.exe wg_profiles_ok.json           # 全部节点
./quixwg.exe wg_profiles_ok.json us.app    # 过滤单节点
WG_TARGET_URL="https://www.cloudflare.com/cdn-cgi/trace" ./quixwg.exe wg_profiles_ok.json
```
原理：每个 profile 起一个完整 WireGuard userspace 设备 + gVisor netstack，真实完成 Noise_IKpsk2 握手并从隧道内发 HTTP —— 返回出口 IP = 密码学与数据面双重确凿证明。

### 3. Demo 面板
```bash
python demo_server.py 8923
# http://127.0.0.1:8923  — 节点清单 / 一键真隧道验证 / 出口 IP + RTT 展示 / conf 导出
```

## 接入自有代理池的路径（文档，未实施）

WireGuard 不是 SOCKS5，接入标准代理池需转换层，两条路：

### 路径 A：网关直嵌（推荐，Go 栈）
- 在 Go 网关内嵌 `wireguard/tun/netstack`（本仓库 `main.go` 即最小可用示例）
- `proxy_pool` 的 proxy 抽象扩展 `wg://<host>:<port>?profile=xxx` scheme
- 拨号时按 scheme 起对应 netstack device，`DialContext` 直通隧道
- 优点：无中间进程、单二进制部署；缺点：网关代码改动

### 路径 B：本地 SOCKS5 转换进程 ✅ 已实现（`quixsocks.go`）
```bash
go build -o quixsocks.exe .
./quixsocks.exe wg_profiles_ok.json 9300
# 节点 i -> socks5://127.0.0.1:(9300+i)，no-auth CONNECT，远端 DNS
# 健康探测 10 分钟一轮（隧道内拉 ipify），状态 http://127.0.0.1:8950/status
curl --socks5-hostname 127.0.0.1:9300 https://api.ipify.org   # 实测出口 207.244.250.147
```
- 4/4 稳定节点（us/in/in2/au2）实测出口 IP 全部正确
- 代理池直接填 `socks5://127.0.0.1:930x`，零网关改动
- 注意：Windows curl(schannel) 需 `--ssl-no-revoke`（吊销检查无法经隧道完成，非代理问题）

### 凭据保鲜
- `getCredentialsV3` 每次返回全新 keypair，可定时（如 6h）重收割轮换
- 收割失败（500）节点自动剔除；配额上限触发前无告警，建议低频轮换

## 文件结构
```
fetch_quix.py            # 单节点凭据领取（核心 API 封装）
harvest_all.py           # 55 节点批量收割（并发 6，自动存 harvest_all.json）
demo_server.py           # demo 面板 :8923（验证/导出/harvest 触发）
main.go                  # wireguard-go netstack 真隧道验证器（quixwg）
wg_profiles_redacted.json# 已脱敏 profile 结构样例
demo_configs/*.conf      # 脱敏 wg-quick 配置样例
serverlist_live.json     # getServerListV3 实抓全量节点
analysis_summary.json    # 静态分析摘要（API/key/端点）
```

## License
MIT
