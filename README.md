# Incus 宿主安全一体化脚本 v6.1.1

违规巡检自愈 + 拦截出站 CN 请求 + 防送中（Google/Apple 等定位上报）。

## 两个脚本

| 文件 | 作用 | 用法 |
|---|---|---|
| `incus-cron.sh` | **部署脚本**（跑一次） | `bash incus-cron.sh [--apply-only\|--scan-only\|--uninstall\|--pin]` |
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

卸载：`bash incus-cron.sh --uninstall`（历史规则快照保留在 `/etc/iptables-custom/snapshot-*.rules`）。

## incus.sh 的三种模式

```bash
bash /usr/local/lib/incus-guard/incus.sh               # 全量：防火墙 + 扫描 + 命中重装
bash /usr/local/lib/incus-guard/incus.sh --apply-only  # 只重建防火墙（开机服务用）
bash /usr/local/lib/incus-guard/incus.sh --scan-only   # 只扫描不重装（验证用）
```

## 名单单一来源

所有域名/端口名单都在 `/etc/iptables-custom/whitelist.conf`，由部署脚本生成，
`incus.sh` 启动时 `source` 它；文件不存在时回落到脚本内置默认值。
改名单只需改这一处，然后重跑部署脚本（或直接编辑该文件，下一轮 cron 生效）。

域名按后缀匹配：写 `speedtest.net` 就等于覆盖 `*.speedtest.net`，不要再写 `*.` 前缀。

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

**3. 测速 / 延迟检测白名单**
38 个常见域名（Ookla/Speedtest、fast.com、Cloudflare、openspeedtest、librespeed、
testmy.net、nperf、ping.pe/sx、captive.apple.com、gstatic、msftconnecttest、
detectportal.firefox.com、ipinfo/ip-api/ip.sb 等）解析出的 IP 自动进
`whitelist_ips_dynamic`，优先于 CN 拦截 → 测速和延迟检测永远能用。

**4. 防送中（拦截定位上报）**
- **SNI 层**（`-m string` 匹配 TLS ClientHello）：`geolocation.googleapis.com`、`geocode.googleapis.com`、`locationhistory`、`userlocation(s).googleapis.com`、`semanticlocation`、`gs-loc(-cn).apple.com`、`.ls.apple.com`、`maps-api.apple.com`、MLS/微软/Skyhook/BeaconDB
- **IP 层**（ipset `geo_v4`）：Apple/微软/Mozilla/Skyhook/BeaconDB 的独立定位端点，每轮刷新
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

## 不劫持宿主 53 端口

旧版会把宿主 UDP/TCP 53 全部 REDIRECT 到 `127.0.0.1:53535` 的 dnsmasq。
**v6.1.0 去掉了这一层**，原因：

- 容器的 DNS 本来就由 incusbr0 自带 dnsmasq 处理（`raw.dnsmasq` 里带同样的
  `ipset=` 指令），解析结果照样写进宿主内核的 `whitelist_ips_dynamic`；
- 宿主去 CN 的流量在 `OUTPUT` 按 `cnip` 网段拦截，不依赖 DNS 黑洞；
- 劫持的唯一好处是宿主自己也走 DNS 黑洞，代价是**dnsmasq 一旦没装/挂了，
  宿主 DNS 立刻全废**，而 `dnsmasq.service` 只随 `dnsmasq` 包提供
  （Incus 只依赖 `dnsmasq-base`），换台新机器必炸。

升级时会自动清理旧版留下的 nat 规则与 `/etc/dnsmasq.d/dynamic_whitelist.conf`，
并在确认该配置没有别的用途后 `systemctl disable --now dnsmasq`。

## 关键修复点（v6.1.0）

- **只升不降**：wrapper 拉远端后比较两侧 `SCRIPT_VERSION`，远端版本更低就拒绝覆盖
  （raw.githubusercontent 的 CDN 缓存能滞后好几分钟，会把刚装好的新脚本换回旧版）。
- **wrapper 透传参数**：`--apply-only` / `--scan-only` 现在真的生效；
  旧版参数被吞，开机兜底 `init.sh` 会退化成全量扫描甚至重装容器。
- **默认远端更新** `ENABLE_REMOTE=1`：每轮拉 `main`，先 `bash -n` 语法门禁，
  失败则沿用本地副本。重跑部署脚本不会再把它悄悄改回 0。
- **`--pin` 可选锁定**：`bash incus-cron.sh --pin` 会把 `PIN_SHA256` 写成当前安装
  那份的哈希，此后远端哈希不符就拒绝执行（等于「必须人工审核才能更新」）。
  默认留空 = 跟随 main。注意：跟随 main 意味着谁有本仓库写权限，谁就能以 root
  在这台机器上执行任意脚本。
- **crontab 写保护**：读现有 crontab 失败（不只是「no crontab」）时直接中止，
  不再可能写入空表把别人的定时任务清掉；写后读回校验。
- **应用前快照**：`/etc/iptables-custom/snapshot-<时间戳>.rules`，保留最近 3 份。
- **logrotate**：`size 5M × 4 + compress`，替代原来只会在有事件时才触发的内联裁剪。
- **超时 240s**：小于 cron 的 300s 间隔，不会再出现一轮吃掉下一轮。
- **首轮返回码**：部署结束按首轮真实 rc 退出并明示成功/失败。
- **名字版本号单一**：`WRAPPER_VERSION` 由部署脚本变量注入，不再有两处写死。
- **镜像源**：只有依赖安装失败才切回官方源（备份 `.bak-incusguard`），
  装得上就绝不动，Debian/Ubuntu 都按发行版和架构选官方地址。

## 回滚

```bash
bash incus-cron.sh --uninstall                     # 推荐
iptables-restore < /etc/iptables-custom/snapshot-<时间戳>.rules   # 恢复旧规则
```

## 已知限制

- 只拦 TCP 443 的 SNI，**UDP/443（HTTP/3）不拦**；ECH 开启时 SNI 非明文会失明
- `www.googleapis.com` 通用入口有意不拦（保 Play 商店）
- 黑洞域名只拦 DNS，容器用 DoH 或直连 IP 可绕过；真正生效的是 `cnip` ipset
- 白名单是「解析到的 IP 放行」，CDN 轮换后最长要等一轮（5 分钟）才更新