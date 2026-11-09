#!/bin/bash
# =======================================================================
# Incus 宿主：违规巡检自愈 + CN 出站拦截 + 防送中（Google/Apple 定位上报）
# v6.0.0  用法：incus.sh [--apply-only|--scan-only]
#   --apply-only  只重建防火墙与防送中规则，不做容器扫描
#   --scan-only   只做容器扫描（不重建防火墙、不重装），用于验证
# 设计要点：
#   1) 规则全部落在自有链（INCUS_GUARD / _OUT / _IN），只保证跳转在  1 号位，
#      不再对系统链做全局大扫除，不会把第三方规则压到放行之后。
#   2) 关键词通过环境变量传入容器、扫描前先快照 PID、并排除自身及直接子进程，
#      彻底消除「脚本扫到自己 argv」造成的误重装（历史 431/458 次）。
#   3) 短关键词只按可执行文件名精确相等匹配，不再做子串匹配。
#   4) 任何一步失败都不静默：防火墙自检不通过就跳过重装，避免误处置。
# =======================================================================

set -uo pipefail

# ============ 白名单 / 黑洞 ============
WHITELIST_DOMAINS=(
    "zstaticcdn.com"
    "*.zstaticcdn.com"
    "*.ooklaserver.net"
    "*.speedtest.net"
    "*.fast.com"
    "speed.cloudflare.com"
)

WHITELIST_IPS=(
    "1.1.1.1"
    "8.8.8.8"
)

BLACKLIST_DOMAINS=(
    "baidu.com" "taobao.com" "qq.com" "jd.com" "bilibili.com" "163.com"
    "weibo.com" "zhihu.com" "douyin.com" "kuaishou.com" "alipay.com"
    "alibaba.com" "tencent.com" "sohu.com" "sina.com" "360.com"
    "iqiyi.com" "youku.com" "xiaohongshu.com" "pinduoduo.com"
    "meituan.com" "ele.me" "aliyun.com"
)

# ============ 违规进程关键词 ============
SCAN_KEYWORDS_LONG="nezha[-_]?agent|komari|xmrig|xmr-stak|minerd|cpuminer|ccminer|cgminer|bfgminer|ethminer|claymore|phoenixminer|nanominer|t-rex|lolminer|nbminer|gminer|teamredminer|nicehash|kryptex|kdevtmpfsi|kinsing|sysrv|sysrv-md|sustse|sustsed|wnw7492|monero|cryptonight|stratum|minergate|poolminer|minerstat|srbminer|astrominer|xmrig-proxy|crypto-miner|hashcat|crypto-pool|gridcrude|pamd32|panchan|p2pinfect|skidmap|watchdogx|watchdogs|kerberods|masscan|rustscan|fscan|gobuster|dirbuster|nikto|wpscan|hydra|medusa|ncrack|crowbar|patator|brutex|ssh_scan|sshcheck|pyrdp|xsstrike|hping|hping3|loic|hoic|slowloris|synflood|udpflood|mirai|gafgyt|bashlite|tsunami|billgates|elknot|dofloo|sedna|stacheldraht|trinoo|kptd|atdd|skynet|gates\.lod|conficker|xorddos|muhstik|frpc|frps|chisel|rclone|ngrok|pagekite|localtonet|vtun|anyconnect|openconnect|iodine|dnscat2|dnscat|3proxy|beacon|geacon|sliver|merlin|metasploit|msfconsole|msfvenom|viper|meterpreter|reasing|neo-regeorg|cmd53|godzilla|behinder|antsword|stowaway|venom|serverstatus|stat_server|stat_client|sergate|beszel-hub|beszel-agent|beszel|nodeget|uptime-kuma|nodequery|prometheus|node_exporter|zabbix_server|zabbix_agentd|grafana-server|grafana|influxd|netdata|glances|cockpit-ws|skywalking|sw-oap-server|vmagent|victoriametrics|fluent-bit|fluentd|logstash|vector|datadog-agent|agent2|filebeat|packetbeat|telegraf|sematext|pinpoint-agent|skywalking-agent|dozzle|scrutiny|sysupdate"

# 短词只按可执行文件名精确相等匹配（已剔除 ew：历史上 431/458 次重装由它引起）
SCAN_BIN_SHORT="lcx nps npc bore suo5 nmap zmap"

# 1-3 人档阈值
MAX_TCP_CONN=800
MAX_UDP_CONN=600
MAX_RAW_CONN=50
MAX_SYN_SENT=80

BLOCK_OUT_PORTS="22,23,445,3389,6379,2375,2376"

# ============ 防送中 ============
# 独立物理 IP 的定位端点（四层拦截）
GEO_DOMAINS="gs-loc.apple.com gs-loc-cn.apple.com gspe1-ssl.ls.apple.com gsp-ssl.ls.apple.com configuration.ls.apple.com maps-api.apple.com location.services.mozilla.com location.microsoft.com inference.location.live.net api.beacondb.net api.skyhookwireless.com"

# 与 Play 商店共用 Anycast IP，只能按 SNI 拦
GEO_SNI_DOMAINS="geolocation.googleapis.com geocode.googleapis.com locationhistory userlocation.googleapis.com userlocations.googleapis.com semanticlocation gs-loc.apple.com gs-loc-cn.apple.com .ls.apple.com maps-api.apple.com location.services.mozilla.com location.microsoft.com inference.location.live.net beacondb.net skyhookwireless.com"

GEO_RESOLVERS="1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222"
IPSET_GEO4="geo_v4"

# ============ 路径 / 链名 ============
CONF_DIR="/etc/iptables-custom"
CNIP_LIST="${CONF_DIR}/cnip.list"
LOG_FILE="/var/log/incus_clean.log"
WRAPPER="/usr/local/bin/incus_cron.sh"
WRAPPER_VERSION="3"
CH_GUARD="INCUS_GUARD"
CH_GUARD_OUT="INCUS_GUARD_OUT"
CH_GUARD_IN="INCUS_GUARD_IN"
CNIP_URL="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/cn/ipv4-aggregated.txt"

MODE="full"
case "${1:-}" in
    --apply-only) MODE="apply" ;;
    --scan-only)  MODE="scan"  ;;
esac

log() { echo "[$(date '+%F %T')] $*"; }

# =======================================================================
ensure_deps() {
    local need=0 b
    for b in ipset iptables curl dig; do
        command -v "$b" >/dev/null 2>&1 || need=1
    done
    [ "$need" -eq 0 ] && return 0
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -yq || true
    apt-get install -yq ipset iptables dnsutils curl cron || true
}

# 宿主 dnsmasq：内容一致就不写不重启
sync_host_dnsmasq() {
    mkdir -p /etc/dnsmasq.d
    local conf="port=53535\nlisten-address=127.0.0.1\nbind-interfaces\n" d c
    for d in "${WHITELIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        conf="${conf}ipset=/${c}/whitelist_ips_dynamic\n"
    done
    for d in "${BLACKLIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        conf="${conf}address=/${c}/0.0.0.0\n"
    done
    conf="${conf}server=8.8.8.8\nserver=1.1.1.1\n"

    local target=/etc/dnsmasq.d/dynamic_whitelist.conf want
    want=$(printf "$conf")
    if [ -f "$target" ] && [ "$(cat "$target")" = "$want" ]; then
        return 0
    fi
    printf "$conf" > "$target"
    systemctl restart dnsmasq >/dev/null 2>&1 || systemctl start dnsmasq >/dev/null 2>&1 || true
    log "dnsmasq 配置更新并重启"
}

# incusbr0 raw.dnsmasq：内容一致就不下发（避免每轮重启容器侧 dnsmasq）
sync_incus_dnsmasq() {
    command -v incus >/dev/null 2>&1 || return 0
    local conf="" d c cur want
    for d in "${WHITELIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        conf="${conf}ipset=/${c}/whitelist_ips_dynamic\n"
    done
    for d in "${BLACKLIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        conf="${conf}address=/${c}/0.0.0.0\n"
    done
    want=$(printf "$conf")
    cur=$(incus network get incusbr0 raw.dnsmasq 2>/dev/null || true)
    [ "$cur" = "$want" ] && return 0
    printf "$conf" | incus network set incusbr0 raw.dnsmasq=- >/dev/null 2>&1 || true
    log "incusbr0 raw.dnsmasq 更新"
}

# CN IP 库：缺失或超 24h 才拉，且校验条数
sync_cnip() {
    mkdir -p "$CONF_DIR"
    if [ -s "$CNIP_LIST" ] && [ -z "$(find "$CNIP_LIST" -mmin +1440 2>/dev/null)" ]; then
        return 0
    fi
    local tmp n
    tmp=$(mktemp)
    if curl -sLf --max-time 60 "$CNIP_URL" | tr -d '\r' | awk '/^[0-9]/ {print "add cnip " $1}' > "$tmp"; then
        n=$(wc -l < "$tmp")
        if [ "${n:-0}" -ge 1000 ]; then
            mv -f "$tmp" "$CNIP_LIST"
            log "CN IP 库更新（${n} 条）"
            tmp=""
        else
            log "CN IP 库条数异常(${n})，沿用旧版"
        fi
    else
        log "CN IP 库拉取失败，沿用旧版"
    fi
    [ -n "$tmp" ] && rm -f "$tmp"
    return 0
}

sync_ipsets() {
    ipset create cnip hash:net 2>/dev/null || ipset flush cnip
    [ -s "$CNIP_LIST" ] && ipset restore -exist < "$CNIP_LIST" 2>/dev/null || true

    ipset create whitelist_ips_static hash:net 2>/dev/null || ipset flush whitelist_ips_static
    ipset create whitelist_ips_dynamic hash:net 2>/dev/null || true

    local ip d c
    for ip in "${WHITELIST_IPS[@]}"; do
        ipset add whitelist_ips_static "$ip" -exist 2>/dev/null || true
    done
    for d in "${WHITELIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        for ip in $(dig +short +time=2 +tries=1 "$c" A 2>/dev/null | grep -E '^[0-9.]+$'); do
            ipset add whitelist_ips_static "$ip" -exist 2>/dev/null || true
        done
    done
    return 0
}

# 定位目标池：临时集合填满后 swap，原子替换；解析全失败则保留旧集合
refresh_geo_ipset() {
    local t4="${IPSET_GEO4}_tmp" d r ip cnt=0
    ipset create "$t4" hash:ip family inet maxelem 65536 -exist
    ipset flush "$t4"
    for d in $GEO_DOMAINS; do
        for r in $GEO_RESOLVERS; do
            for ip in $(dig +short +time=2 +tries=1 "@$r" A "$d" 2>/dev/null | grep -E '^[0-9.]+$'); do
                ipset add "$t4" "$ip" -exist 2>/dev/null && cnt=$((cnt+1))
            done
        done
    done
    if [ "$cnt" -gt 0 ]; then
        ipset create "$IPSET_GEO4" hash:ip family inet maxelem 65536 -exist
        ipset swap "$t4" "$IPSET_GEO4" >/dev/null 2>&1 && ipset destroy "$t4" 2>/dev/null
    else
        ipset destroy "$t4" 2>/dev/null
        ipset create "$IPSET_GEO4" hash:ip family inet maxelem 65536 -exist
        log "定位目标池解析全部失败，沿用旧集合"
    fi
    return 0
}

have_xt_string() { iptables -m string --help 2>&1 | grep -q -- "--algo"; }

# 重建单个自有链（链内替换，不碰系统链）
fill_chain() {
    local ch=$1 scope=$2 d
    iptables -F "$ch" 2>/dev/null || return 0

    # ① 防送中 SNI 熔断（最优先；只做 443，定位上报不走明文 HTTP）
    if have_xt_string && [ "$scope" != "in" ]; then
        for d in $GEO_SNI_DOMAINS; do
            iptables -A "$ch" -p tcp --dport 443 -m string --string "$d" --algo bm -j REJECT --reject-with tcp-reset 2>/dev/null
        done
    fi

    # ② 防送中 独立 IP 定位端点
    if [ "$scope" != "in" ]; then
        iptables -A "$ch" -m set --match-set "$IPSET_GEO4" dst -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null
        iptables -A "$ch" -m set --match-set "$IPSET_GEO4" dst -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    fi

    # ③ 测速类白名单（优先于 CN 拦截）
    iptables -A "$ch" -m set --match-set whitelist_ips_dynamic dst -j ACCEPT 2>/dev/null
    iptables -A "$ch" -m set --match-set whitelist_ips_static dst -j ACCEPT 2>/dev/null

    # ④ .cn DNS 拦截（forward/in 限定 incusbr0，out 不限接口）
    if have_xt_string; then
        local iif=""
        if [ "$scope" = "forward" ] || [ "$scope" = "in" ]; then
            iif="-i incusbr0"
        fi
        iptables -A "$ch" $iif -p tcp --dport 53 -m string --hex-string "|02636e00|" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        iptables -A "$ch" $iif -p udp --dport 53 -m string --hex-string "|02636e00|" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        iptables -A "$ch" $iif -p tcp --dport 53 -m string --hex-string "|02434e00|" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        iptables -A "$ch" $iif -p udp --dport 53 -m string --hex-string "|02434e00|" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    fi

    if [ "$scope" = "forward" ]; then
        # ⑤ 容器出站高危端口
        [ -n "$BLOCK_OUT_PORTS" ] && \
            iptables -A "$ch" -i incusbr0 -p tcp -m multiport --dports "$BLOCK_OUT_PORTS" -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        # ⑥ 拦截去往 CN 的新连接
        iptables -A "$ch" -i incusbr0 -m set --match-set cnip dst -p tcp --syn -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        iptables -A "$ch" -i incusbr0 -m set --match-set cnip dst -p udp -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        # ⑦ 兜底放行（放行必须在拦截之后）
        iptables -A "$ch" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        iptables -A "$ch" -i incusbr0 -j ACCEPT 2>/dev/null
        iptables -A "$ch" -o incusbr0 -j ACCEPT 2>/dev/null
    elif [ "$scope" = "out" ]; then
        # ⑥ 宿主自身 → CN 的新连接
        iptables -A "$ch" -m set --match-set cnip dst -p tcp --syn -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
        iptables -A "$ch" -m set --match-set cnip dst -p udp -m conntrack --ctstate NEW -j REJECT --reject-with icmp-port-unreachable 2>/dev/null
    fi
    return 0
}

ensure_top() {
    local chain=$1 target=$2 idx
    if ! iptables -C "$chain" -j "$target" 2>/dev/null; then
        iptables -I "$chain" 1 -j "$target" 2>/dev/null && log "挂载 $target -> $chain"
        return 0
    fi
    idx=$(iptables -L "$chain" --line-numbers -n 2>/dev/null | awk -v t="$target" '$2==t{print $1; exit}')
    if [ "${idx:-0}" != "1" ]; then
        iptables -D "$chain" -j "$target" 2>/dev/null
        iptables -I "$chain" 1 -j "$target" 2>/dev/null
        log "$target 在 $chain 被挤到第 ${idx} 位，已复位"
    fi
    return 0
}

apply_firewall() {
    mkdir -p "$CONF_DIR"
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    iptables -N "$CH_GUARD"     2>/dev/null || true
    iptables -N "$CH_GUARD_OUT" 2>/dev/null || true
    iptables -N "$CH_GUARD_IN"  2>/dev/null || true

    # nat：宿主 DNS 劫持（幂等）
    iptables -t nat -C OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null || \
        iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null
    iptables -t nat -C OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null || \
        iptables -t nat -I OUTPUT 1 -p tcp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null
    local uid
    for uid in dnsmasq nobody; do
        iptables -t nat -C OUTPUT -p udp --dport 53 -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null || \
            iptables -t nat -I OUTPUT 1 -p udp --dport 53 -m owner --uid-owner "$uid" -j ACCEPT 2>/dev/null
    done

    fill_chain "$CH_GUARD" forward
    fill_chain "$CH_GUARD_OUT" out
    fill_chain "$CH_GUARD_IN" in

    ensure_top FORWARD "$CH_GUARD"
    ensure_top OUTPUT  "$CH_GUARD_OUT"
    ensure_top INPUT   "$CH_GUARD_IN"
    return 0
}

self_check() {
    local bad=""
    iptables -C FORWARD -j "$CH_GUARD"     2>/dev/null || bad="$bad FORWARD跳转"
    iptables -C OUTPUT  -j "$CH_GUARD_OUT" 2>/dev/null || bad="$bad OUTPUT跳转"
    iptables -C INPUT   -j "$CH_GUARD_IN"  2>/dev/null || bad="$bad INPUT跳转"
    ipset list -n 2>/dev/null | grep -qx cnip || bad="$bad CN网段"
    ipset list -n 2>/dev/null | grep -qx "$IPSET_GEO4" || bad="$bad 定位池"
    iptables -S "$CH_GUARD" 2>/dev/null | grep -q -- "$IPSET_GEO4" || bad="$bad 防送中规则"
    if [ -n "$bad" ]; then
        echo "FATAL: 防火墙不完整:$bad"
        return 1
    fi
    return 0
}

ensure_wrapper() {
    [ -f "$WRAPPER" ] || return 0
    local v
    v=$(grep -m1 '^WRAPPER_VERSION=' "$WRAPPER" 2>/dev/null | sed 's/.*="\([^"]*\)".*/\1/')
    if [ "${v:-0}" != "$WRAPPER_VERSION" ]; then
        log "检测到 wrapper 版本 ${v:-未知}（期望 ${WRAPPER_VERSION}），请重跑部署脚本升级"
    fi
    return 0
}

# =======================================================================
case "$MODE" in
    apply|full)
        ensure_deps
        sync_cnip
        sync_ipsets
        sync_host_dnsmasq
        [ "$MODE" = "full" ] && sync_incus_dnsmasq
        refresh_geo_ipset
        apply_firewall
        if ! self_check; then
            exit 1
        fi
        log "防火墙 + CN 拦截 + 防送中规则已应用"
        [ "$MODE" = "apply" ] && exit 0
        ;;
    scan)
        log "scan-only：跳过防火墙重建"
        ;;
esac

ensure_wrapper

command -v incus >/dev/null 2>&1 || { log "未发现 incus，跳过容器扫描"; exit 0; }

TARGET_IMAGE=""
local_alpine=$(incus image list local: -f csv -c fd 2>/dev/null | grep -i alpine | head -n1 | cut -d, -f1)
if [ -n "$local_alpine" ]; then
    TARGET_IMAGE="$local_alpine"
else
    local_any=$(incus image list local: -f csv -c f 2>/dev/null | head -n1)
    TARGET_IMAGE="${local_any:-images:alpine/latest}"
fi

PROJECT_LIST=$(incus project list -f csv -c n 2>/dev/null)
[ -z "$PROJECT_LIST" ] && PROJECT_LIST="default"

COUNT=0
HIT=0

for project in $PROJECT_LIST; do
    [ -z "$project" ] && continue
    RUNNING=$(incus list --project "$project" -f csv -c ns 2>/dev/null | awk -F, 'tolower($0) ~ /,running$/ {print $1}')
    for c in $RUNNING; do
        [ -z "$c" ] && continue
        COUNT=$((COUNT+1))
        printf "[%d] 正在盘查: %-26s [项目: %-8s] -> " "$COUNT" "$c" "$project"

        HIT_REASON=$(timeout 60 incus exec --project "$project" \
            --env KL="$SCAN_KEYWORDS_LONG" \
            --env KB="$SCAN_BIN_SHORT" \
            --env MT="$MAX_TCP_CONN" \
            --env MU="$MAX_UDP_CONN" \
            --env MR="$MAX_RAW_CONN" \
            --env MS="$MAX_SYN_SENT" \
            "$c" -- sh -c '
                KW_LONG="$KL"; KW_BIN="$KB"
                [ -f /proc/net/tcp ] || exit 0
                PIDS=$(ls -d /proc/[0-9]* 2>/dev/null | sed "s|/proc/||")

                TCP_C=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -cv "sl")
                UDP_C=$(cat /proc/net/udp /proc/net/udp6 2>/dev/null | grep -cv "sl")
                RAW_C=$(cat /proc/net/raw /proc/net/raw6 2>/dev/null | grep -cv "sl")
                SYN_C=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk "{print \$4}" | grep -cx "02")

                [ "${SYN_C:-0}" -gt "$MS" ] && { echo "异常开包扫描 ($SYN_C)"; exit 0; }
                [ "${TCP_C:-0}" -gt "$MT" ] && { echo "TCP高并发 ($TCP_C)"; exit 0; }
                [ "${UDP_C:-0}" -gt "$MU" ] && { echo "UDP洪水 ($UDP_C)"; exit 0; }
                [ "${RAW_C:-0}" -gt "$MR" ] && { echo "伪造Raw协议 ($RAW_C)"; exit 0; }

                ME=$$; MEP=$(awk "{print \$4}" /proc/$ME/stat 2>/dev/null)
                for p in $PIDS; do
                    [ -r /proc/$p/cmdline ] || continue
                    [ "$p" = "$ME" ] && continue
                    [ "$p" = "$MEP" ] && continue
                    PP=$(awk "{print \$4}" /proc/$p/stat 2>/dev/null)
                    [ "$PP" = "$ME" ] && continue

                    TXT=$(tr "\0" "\n" < /proc/$p/cmdline 2>/dev/null)
                    [ -z "$TXT" ] && continue

                    M=$(echo "$TXT" | grep -oiE "$KW_LONG" | head -n1)
                    [ -n "$M" ] && { echo "违规进程: $M"; exit 0; }

                    BIN=$(readlink /proc/$p/exe 2>/dev/null)
                    [ -z "$BIN" ] && BIN=$(echo "$TXT" | head -n1)
                    B=$(basename "$BIN" 2>/dev/null)
                    for w in $KW_BIN; do
                        [ "$B" = "$w" ] && { echo "违规进程: $B"; exit 0; }
                    done
                done

                for f in /opt/nezha/agent/nezha-agent /usr/local/bin/nezha-agent /usr/local/bin/nezha_agent /root/nezha-agent /etc/init.d/nezha-agent /etc/systemd/system/nezha-agent.service; do
                    [ -e "$f" ] && { echo "残留文件: $f"; exit 0; }
                done
            ' < /dev/null 2>/dev/null)

        if [ -n "$HIT_REASON" ]; then
            HIT=$((HIT+1))
            echo "【🚨 违规: $HIT_REASON】"
            if [ "$MODE" = "scan" ]; then
                echo "   ↳ (scan-only，未执行重装)"
            else
                echo "   ↳ 🔄 强制执行抹除性重装自愈..."
                if timeout 300 incus rebuild --project "$project" "$TARGET_IMAGE" "$c" --force < /dev/null >/dev/null 2>&1; then
                    echo "   ↳ ✅ 重装成功！"
                else
                    echo "   ↳ ❌ 重装失败（镜像 $TARGET_IMAGE）"
                fi
            fi
        else
            echo "[✔ 正常]"
        fi
    done
done

echo "------------------------------------------------"
log "巡检结束：盘查 ${COUNT} 台，命中 ${HIT} 台"