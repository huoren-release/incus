# Incus 宿主安全一体化脚本 v6.0.0

违规巡检自愈 + 拦截出站 CN 请求 + 防送中（Google/Apple 等定位上报）。

## 两个脚本

| 文件 | 作用 | 用法 |
|---|---|---|
| `incus-cron.sh` | **部署脚本**（跑一次） | `bash incus-cron.sh` |
| `incus.sh` | **执行体**（每 5 分钟由 cron 调用） | 由 wrapper 调用，也可手动 `--apply-only` / `--scan-only` |

## 一键部署

```bash
mkdir -p /root/iguard-src && cd /root/iguard-src
curl -fsSL -o incus.sh      https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh
curl -fsSL -o incus-cron.sh https://raw.githubusercontent.com/huoren-release/incus/main/incus-cron.sh
bash incus-cron.sh
```

部署脚本会把 `incus.sh` 安装到 `/usr/local/lib/incus-guard/incus.sh`，
并生成 wrapper `/usr/local/bin/incus_cron.sh` + crontab（每 5 分钟）。

## incus.sh 的三种模式

```bash
bash /usr/local/lib/incus-guard/incus.sh               # 全量：防火墙 + 扫描 + 命中重装
bash /usr/local/lib/incus-guard/incus.sh --apply-only  # 只重建防火墙（开机服务用）
bash /usr/local/lib/incus-guard/incus.sh --scan-only   # 只扫描不重装（验证用）
```

## 功能

**1. 违规检测与重装**
- 扫每个运行中容器的 `/proc` 命令行（挖矿/扫描器/隧道/探针等 200+ 关键词）
- 连接数阈值：TCP>800、UDP>600、RAW>50、SYN>80（1-3 人档）
- 命中即 `incus rebuild --force` 重装

**2. 拦截出站 CN 请求**
- ipset `cnip`（ipverse 数据，>24h 自动刷新）+ 拦容器/宿主去 CN 的新连接
- DNS 层拦 `.cn` 后缀（`|02636e00|` / `|02434e00|`）
- 容器出站高危端口 22/23/445/3389/6379/2375/2376
- 黑洞域名（百度/淘宝/QQ 等 23 条）在 dnsmasq 层导 0.0.0.0

**3. 防送中（拦截定位上报）**
- **SNI 层**（`-m string` 匹配 TLS ClientHello）：`geolocation.googleapis.com`、`geocode.googleapis.com`、`locationhistory`、`userlocation(s).googleapis.com`、`semanticlocation`、`gs-loc(-cn).apple.com`、`.ls.apple.com`、`maps-api.apple.com`、MLS/微软/Skyhook/BeaconDB
- **IP 层**（ipset `geo_v4`）：Apple/微软/Mozilla/Skyhook/BeaconDB 的独立定位端点，2 小时刷新
- Google 定位与 Play 商店共用 Anycast IP，所以按 SNI 拦、不按 IP 拦 —— Play 不受影响

## 架构：独立链，不抢系统链

```
FORWARD → INCUS_GUARD (第 1 位)
OUTPUT  → INCUS_GUARD_OUT (第 1 位)
INPUT   → INCUS_GUARD_IN (第 1 位)
```

每轮只 `flush` 自己的链再重建，**不对系统链做全局大扫除**。
每轮用 `ensure_top` 检查跳转是否被挤下去，挤下去就复位。

这样第三方规则（例如另一套防送中脚本）挂在系统链上也仍然生效，
不会被本脚本的 `-j ACCEPT` 兜底规则压到后面。

## 键修复点（v6.0.0）

- **修复误重装**：关键词改走 `incus exec --env`（不进 argv），扫描前先快照 PID，
  并排除自身及直接子进程 → 消灭「脚本扫到自己命令行」的误判。
  历史日志里 458 次重装中有 **431 次是 `违规进程: ew`** 的误杀。
- **短关键词**改为按可执行文件名精确相等（`lcx nps npc bore suo5 nmap zmap`），
  不再做 `-w` 子串匹配；`ew` 已剔除。
- **wrapper 加 flock**：上一轮没跑完就跳过，避免 `*/5` 撞 10 分钟上限。
- **失败不静默**：非零退出、耗时 >300s、防火墙自检不通过都写日志。
- **不删 `/etc/resolv.conf`**：旧版 `rm -f` 在 bind 挂载的机器上会 EBUSY 直接崩，
  且会覆盖厂商 DNS。
- **sha256 pin + 远端开关**：`ENABLE_REMOTE=0` 只跑本地副本；改 1 后每轮拉远端并校验。
- **CN IP 库校验条数**：<1000 条视为异常，保留旧版。

## 回滚

```bash
crontab -l | grep -v incus_cron.sh | crontab -
rm -f /usr/local/bin/incus_cron.sh /usr/local/lib/incus-guard/incus.sh
rm -f /etc/systemd/system/custom-firewall.service
systemctl daemon-reload
iptables -D FORWARD -j INCUS_GUARD; iptables -F INCUS_GUARD; iptables -X INCUS_GUARD
iptables -D OUTPUT  -j INCUS_GUARD_OUT; iptables -F INCUS_GUARD_OUT; iptables -X INCUS_GUARD_OUT
iptables -D INPUT   -j INCUS_GUARD_IN;  iptables -F INCUS_GUARD_IN;  iptables -X INCUS_GUARD_IN
ipset destroy geo_v4
```

## 已知限制

- 只拦 TCP 443 的 SNI，**UDP/443（HTTP/3）不拦**；ECH 开启时 SNI 非明文会失明
- `www.googleapis.com` 通用入口有意不拦（保 Play 商店）
- 黑洞域名只拦 DNS，容器用 DoH 或直连 IP 可绕过；真正生效的是 `cnip` ipset
