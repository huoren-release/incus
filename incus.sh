#!/bin/bash
# =======================================================================
# Incus 宿主：违规巡检自愈 + CN 出站拦截 + 防送中（Google/Apple 定位上报）
# v6.2.9  用法：incus.sh [--apply-only|--scan-only]
#   --apply-only  只重建防火墙与防送中规则，不做容器扫描
#   --scan-only   只做容器扫描（不重建防火墙、不重装），用于验证
# 设计要点：
#   1) 规则全部落在自有链（INCUS_GUARD / _OUT / _IN），只保证跳转在 1 号位，
#      不再对系统链做全局大扫除，不会把第三方规则压到放行之后。
#   2) 关键词通过环境变量传入容器、扫描前先快照 PID、并排除自身及直接子进程，
#      彻底消除「脚本扫到自己 argv」造成的误重装（历史 431/458 次）。
#   3) 关键词只匹配「参数的文件名部分」与可执行文件名，不再对整条 cmdline
#      做子串匹配 —— /etc/prometheus/x.yml 这类路径不会再误伤。
#   4) 任何一步失败都不静默：防火墙自检不通过就跳过重装；重装失败必须带
#      incus 的原始报错，并回读容器状态，不是 RUNNING 就报警。
#   5) 不再劫持宿主 53 端口：容器 DNS 走 incusbr0 自带 dnsmasq，宿主去 CN
#      的流量在 OUTPUT 按网段拦截，去掉「dnsmasq 挂了宿主 DNS 全废」的故障点。
#   6) 名单单一来源：/etc/iptables-custom/whitelist.conf（部署脚本生成）。
#   7) 重装镜像按容器自己的基础镜像挑，挑不到就拒绝处置（v6.2.0）。
#      v6.1.x 无本地镜像时回退到 images:alpine/latest，该别名并不存在，
#      导致 rebuild 先停容器再取镜像失败，把用户容器留在 STOPPED。
#   8) IPv4/IPv6 双栈：ip6tables 建同名自有链，CN v6 网段与定位 v6 池一并拦截。
#   9) 白名单静态池「先解析到临时集合、达标才 swap」，DNS 抖动不会清空池子。
#  10) 动态白名单池带 2h 默认超时，IP 换主后不会永久豁免。
#  11) UDP 拦截是「有状态」的：只拦 conntrack 状态 NEW 的首包（= 容器主动外连），大陆
#      客户端打进来的 UDP 会话，容器回包是 ESTABLISHED，照常放行。这套机制依赖 conntrack
#      撑得住：默认 udp 超时 30s/120s、表上限低到 65536/7680，条目一旦过期或被驱逐，
#      回包就会被重新算成 NEW、按「主动外连」打掉，表现为 UDP「连得上但时通时断」
#      → 每轮由 ensure_conntrack_tuning 把时长/上限抬上去（只升不降）。
#  12) 重装后必须补系统级初始化（v6.2.9）：rebuild 是裸装镜像，openssh 没装、sshd
#      没进运行级。面板「重装系统」建好后会初始化，巡检不走那条路，客户被抹之后
#      就成了谁也登不进去的空壳（u3031 空转 5 天）。现在重装成功即装 openssh、
#      生成 host key、写 sshd_config、sshd 进 default 运行级并启动，并把重装前
#      抓到的 root 密码散列经 stdin 写回；不装节点/面板软件，也不碰公钥（面板重装才注入）。
# =======================================================================

set -uo pipefail

# 执行体版本：wrapper 用它做「只升不降」判断，防止 CDN 缓存把本地副本换成旧版
SCRIPT_VERSION="6.2.9"

CONF_DIR="/etc/iptables-custom"
GUARD_CONF="${CONF_DIR}/whitelist.conf"

# ============ 默认名单（可被 whitelist.conf 覆盖）============
# 域名按后缀匹配：写 speedtest.net 即覆盖 *.speedtest.net，不需要再写 *. 前缀
DEFAULT_WHITELIST_DOMAINS="speedtest.net ookla.com ooklaserver.net speedtestcustom.com \
fast.com nflxvideo.net nflximg.net nflxext.net nflxso.net \
cloudflare.com one.one.one.one \
openspeedtest.com librespeed.org speedof.me testmy.net bandwidthplace.com nperf.com \
waveform.com speedcheck.org \
captive.apple.com gstatic.com clients3.google.com clients4.google.com \
msftconnecttest.com msftncsi.com detectportal.firefox.com connectivity-check.ubuntu.com \
ping.pe ping.sx ping0.cc \
ip.sb ipinfo.io ip-api.com ipwho.is ifconfig.me icanhazip.com checkip.amazonaws.com \
zstaticcdn.com \
sh-ct-v4.ip.zstaticcdn.com sh-cu-v4.ip.zstaticcdn.com sh-cm-v4.ip.zstaticcdn.com \
sd-ct-v4.ip.zstaticcdn.com sd-cu-v4.ip.zstaticcdn.com sd-cm-v4.ip.zstaticcdn.com"

DEFAULT_WHITELIST_IPS="1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 208.67.222.222"
DEFAULT_WHITELIST_IPS6="2606:4700:4700::1111 2606:4700:4700::1001 2001:4860:4860::8888 2001:4860:4860::8844 2620:fe::fe 2620:119:35::35"

DEFAULT_BLACKLIST_DOMAINS="baidu.com taobao.com qq.com jd.com bilibili.com 163.com \
weibo.com zhihu.com douyin.com kuaishou.com alipay.com alibaba.com tencent.com sohu.com \
sina.com 360.com iqiyi.com youku.com xiaohongshu.com pinduoduo.com meituan.com ele.me \
aliyun.com"

DEFAULT_BLOCK_OUT_PORTS="22,23,445,3389,6379,2375,2376"

WHITELIST_DOMAINS=()
WHITELIST_IPS=()
WHITELIST_IPS6=()
BLACKLIST_DOMAINS=()
BLOCK_OUT_PORTS=""

load_conf() {
    if [ -r "$GUARD_CONF" ]; then
        # shellcheck disable=SC1090
        . "$GUARD_CONF" || true
    fi
    [ "${#WHITELIST_DOMAINS[@]}" -eq 0 ] && read -r -a WHITELIST_DOMAINS <<< "$DEFAULT_WHITELIST_DOMAINS"
    [ "${#WHITELIST_IPS[@]}" -eq 0 ]     && read -r -a WHITELIST_IPS     <<< "$DEFAULT_WHITELIST_IPS"
    [ "${#WHITELIST_IPS6[@]}" -eq 0 ]    && read -r -a WHITELIST_IPS6    <<< "$DEFAULT_WHITELIST_IPS6"
    [ "${#BLACKLIST_DOMAINS[@]}" -eq 0 ] && read -r -a BLACKLIST_DOMAINS <<< "$DEFAULT_BLACKLIST_DOMAINS"
    [ -z "${BLOCK_OUT_PORTS:-}" ]        && BLOCK_OUT_PORTS="$DEFAULT_BLOCK_OUT_PORTS"
    return 0
}

# 去重后的域名列表（统一去掉 *. 前缀，dnsmasq / ipset 都按后缀匹配）
uniq_wl_domains() {
    local d
    for d in "${WHITELIST_DOMAINS[@]}"; do echo "${d#\*.}"; done | sed '/^$/d' | sort -u
}
uniq_bl_domains() {
    local d
    for d in "${BLACKLIST_DOMAINS[@]}"; do echo "${d#\*.}"; done | sed '/^$/d' | sort -u
}

# ============ 违规进程关键词 ============
SCAN_KEYWORDS_LONG="nezha[-_]?agent|komari|xmrig|xmr-stak|minerd|cpuminer|ccminer|cgminer|bfgminer|ethminer|claymore|phoenixminer|nanominer|t-rex|lolminer|nbminer|gminer|teamredminer|nicehash|kryptex|kdevtmpfsi|kinsing|sysrv|sysrv-md|sustse|sustsed|wnw7492|monero|cryptonight|stratum|minergate|poolminer|minerstat|srbminer|astrominer|xmrig-proxy|crypto-miner|hashcat|crypto-pool|gridcrude|pamd32|panchan|p2pinfect|skidmap|watchdogx|watchdogs|kerberods|masscan|rustscan|fscan|gobuster|dirbuster|nikto|wpscan|hydra|medusa|ncrack|crowbar|patator|brutex|ssh_scan|sshcheck|pyrdp|xsstrike|hping|hping3|loic|hoic|slowloris|synflood|udpflood|mirai|gafgyt|bashlite|tsunami|billgates|elknot|dofloo|sedna|stacheldraht|trinoo|kptd|atdd|skynet|gates\\.lod|conficker|xorddos|muhstik|frpc|frps|chisel|rclone|ngrok|pagekite|localtonet|vtun|anyconnect|openconnect|iodine|dnscat2|dnscat|3proxy|beacon|geacon|sliver|merlin|metasploit|msfconsole|msfvenom|viper|meterpreter|reasing|neo-regeorg|cmd53|godzilla|behinder|antsword|stowaway|venom|serverstatus|stat_server|stat_client|sergate|beszel-hub|beszel-agent|beszel|nodeget|uptime-kuma|nodequery|prometheus|node_exporter|zabbix_server|zabbix_agentd|grafana-server|grafana|influxd|netdata|glances|cockpit-ws|skywalking|sw-oap-server|vmagent|victoriametrics|fluent-bit|fluentd|logstash|vector|datadog-agent|agent2|filebeat|packetbeat|telegraf|sematext|pinpoint-agent|skywalking-agent|dozzle|scrutiny|sysupdate"

# 短词只按可执行文件名精确相等匹配（已剔除 ew：历史上 431/458 次重装由它引起）
SCAN_BIN_SHORT="lcx nps npc bore suo5 nmap zmap"

# 1-3 人档阈值（用户确认保持现状，不随性能调整）
MAX_TCP_CONN=800
MAX_UDP_CONN=600
MAX_RAW_CONN=50
MAX_SYN_SENT=80

# ============ 防送中 ============
# 独立物理 IP 的定位端点（IP 层拦截）
GEO_DOMAINS="gs-loc.apple.com gs-loc-cn.apple.com gspe1-ssl.ls.apple.com gsp-ssl.ls.apple.com configuration.ls.apple.com maps-api.apple.com location.services.mozilla.com location.microsoft.com inference.location.live.net api.beacondb.net api.skyhookwireless.com"

# 与 Play 商店共用 Anycast IP，只能按 SNI 拦
GEO_SNI_DOMAINS="geolocation.googleapis.com geocode.googleapis.com locationhistory userlocation.googleapis.com userlocations.googleapis.com semanticlocation gs-loc.apple.com gs-loc-cn.apple.com .ls.apple.com maps-api.apple.com location.services.mozilla.com location.microsoft.com inference.location.live.net beacondb.net skyhookwireless.com"

GEO_RESOLVERS="1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222"
IPSET_GEO4="geo_v4"
IPSET_GEO6="geo_v6"

# ============ 路径 / 链名 ============
CNIP_LIST="${CONF_DIR}/cnip.list"
CNIP6_LIST="${CONF_DIR}/cnip6.list"
WRAPPER="/usr/local/bin/incus_cron.sh"
WRAPPER_VERSION="8"
CH_GUARD="INCUS_GUARD"
CH_GUARD_OUT="INCUS_GUARD_OUT"
CH_GUARD_IN="INCUS_GUARD_IN"
CNIP_URL="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/cn/ipv4-aggregated.txt"
CNIP6_URL="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/cn/ipv6-aggregated.txt"
HOST_DNS_PORT="53535"

MODE="full"
case "${1:-}" in
    --apply-only) MODE="apply" ;;
    --scan-only)  MODE="scan"  ;;
esac

log() { echo "[$(date '+%F %T')] $*"; }

load_conf

# =======================================================================
ensure_deps() {
    local need=0 b
    for b in ipset iptables ip6tables curl dig; do
        command -v "$b" >/dev/null 2>&1 || need=1
    done
    [ "$need" -eq 0 ] && return 0
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -yq || true
    apt-get install -yq ipset iptables dnsutils curl cron util-linux || true
}

have_v6() { command -v ip6tables >/dev/null 2>&1 && ip6tables -L -n >/dev/null 2>&1; }

# conntrack 时长/上限：UDP 没有握手，全靠 conntrack 状态区分「回包」与「主动外连」。
# 默认 udp_timeout=30s / udp_timeout_stream=120s、nf_conntrack_max 最小可到 7680 条，
# 一旦过期或表满，容器回包会被重新算成 NEW，被 CN 拦截规则打掉，表现为 UDP 时通时断。
# 只升不降：不覆盖运维手工调大的值；每轮重刷，重启后由开机任务/cron 重新应用。
ensure_conntrack_tuning() {
    local base=/proc/sys/net/netfilter mem_mb want
    [ -r "$base/nf_conntrack_udp_timeout" ] || return 0
    tune_ge() {
        local k=$1 v=$2 cur
        [ -r "$base/$k" ] || return 0
        cur=$(cat "$base/$k" 2>/dev/null || echo "")
        case "${cur:-}" in ''|*[!0-9]*) return 0 ;; esac
        [ "$cur" -ge "$v" ] && return 0
        printf '%s' "$v" > "$base/$k" 2>/dev/null && log "conntrack $k: $cur -> $v"
        return 0
    }
    tune_ge nf_conntrack_udp_timeout 180          # 默认 30：只发了包、还没回包的会话
    tune_ge nf_conntrack_udp_timeout_stream 600   # 默认 120：已有来回收发（QUIC/hysteria2/tuic）
    mem_mb=$(( $(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0) / 1024 ))
    want=262144
    [ "${mem_mb:-0}" -lt 2048 ] && want=131072
    [ "${mem_mb:-0}" -lt 1024 ] && want=65536
    tune_ge nf_conntrack_max "$want"
    return 0
}

# incusbr0 raw.dnsmasq：容器侧 dnsmasq 负责填充白名单池与 CN 域名黑洞
sync_incus_dnsmasq() {
    command -v incus >/dev/null 2>&1 || return 0
    local conf="" d cur want
    for d in $(uniq_wl_domains); do
        conf="${conf}ipset=/${d}/whitelist_ips_dynamic\\n"
    done
    for d in $(uniq_bl_domains); do
        conf="${conf}address=/${d}/0.0.0.0\\naddress=/${d}/::\\n"
    done
    want=$(printf '%b' "$conf")
    cur=$(incus network get incusbr0 raw.dnsmasq 2>/dev/null || true)
    [ "$cur" = "$want" ] && return 0
    printf '%b' "$conf" | incus network set incusbr0 raw.dnsmasq=- >/dev/null 2>&1 || true
    log "incusbr0 raw.dnsmasq 更新"
}

# 清理旧版留下的宿主 DNS 劫持（v6.0.0 及更早会做）
# 只删我们自己加的 REDIRECT，不动别人加的 -m owner ACCEPT
cleanup_legacy_dns_hijack() {
    local n=0
    while iptables -t nat -C OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" 2>/dev/null; do
        iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" 2>/dev/null || break
        n=$((n+1))
    done
    while iptables -t nat -C OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" 2>/dev/null; do
        iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$HOST_DNS_PORT" 2>/dev/null || break
        n=$((n+1))
    done
    if [ -f /etc/dnsmasq.d/dynamic_whitelist.conf ]; then
        rm -f /etc/dnsmasq.d/dynamic_whitelist.conf
        n=$((n+1))
        local others
        others=$(ls /etc/dnsmasq.d 2>/dev/null | grep -v '^README$' | grep -v 'dynamic_whitelist.conf' | wc -l)
        if [ "${others:-0}" -eq 0 ]; then
            systemctl disable --now dnsmasq >/dev/null 2>&1 || true
            log "宿主 dnsmasq 已停用（不再劫持 53）"
        fi
    fi
    [ "$n" -gt 0 ] && log "已清理旧版宿主 DNS 劫持与配置"
    return 0
}

# 清掉旧版（v6.0.0 及更早）直接塞在系统链里的 ipset 规则。
# 它们会一直留着：既重复豁免，又让对应 ipset 永远无法 destroy（References 归零不了）。
cleanup_legacy_rules() {
    local ipt ch set line spec n=0
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        for ch in FORWARD OUTPUT INPUT; do
            for set in cnip cnip6 geo_v4 geo_v6 whitelist_ips_dynamic whitelist_ips_dynamic6 \
                       whitelist_ips_static whitelist_ips_static6; do
                while line=$($ipt -S "$ch" 2>/dev/null | grep -m1 -- "-m set --match-set $set "); do
                    spec="${line#-A $ch }"
                    # shellcheck disable=SC2086
                    $ipt -D "$ch" $spec 2>/dev/null || break
                    n=$((n+1))
                done
            done
        done
    done
    [ "$n" -gt 0 ] && log "已清理旧版残留在系统链里的 ${n} 条 ipset 规则"
    return 0
}

# CN IP 库：缺失或超 24h 才拉；条数达标才落地，绝不用空库覆盖旧库
sync_cnip_list() {
    local url=$1 list=$2 min=$3 setname=$4
    mkdir -p "$CONF_DIR"
    if [ -s "$list" ] && [ -z "$(find "$list" -mmin +1440 2>/dev/null)" ]; then
        return 0
    fi
    local tmp n
    tmp=$(mktemp)
    if curl -sLf --max-time 60 "$url" 2>/dev/null | tr -d '\r' \
        | awk -v s="$setname" '/^[0-9a-fA-F:.]+(\/[0-9]+)?$/ {print "add " s " " $1}' > "$tmp"; then
        n=$(wc -l < "$tmp")
        if [ "${n:-0}" -ge "$min" ]; then
            mv -f "$tmp" "$list"
            log "CN 库更新 $setname（${n} 条）"
            tmp=""
        else
            log "CN 库 $setname 条数异常(${n})，沿用旧版"
        fi
    else
        log "CN 库 $setname 拉取失败，沿用旧版"
    fi
    [ -n "$tmp" ] && rm -f "$tmp"
    return 0
}

sync_cnip() {
    sync_cnip_list "$CNIP_URL"  "$CNIP_LIST"  1000 cnip
    have_v6 && sync_cnip_list "$CNIP6_URL" "$CNIP6_LIST" 100 cnip6
}

# 并发解析整份白名单，输出一行一个 IP
resolve_whitelist() {
    local rrtype=$1 out d
    out=$(mktemp)
    for d in $(uniq_wl_domains); do
        ( dig +short +time=1 +tries=1 "$d" "$rrtype" 2>/dev/null \
            | grep -E '^[0-9a-fA-F:.]+$' >> "$out" ) &
    done
    wait
    sort -u "$out" 2>/dev/null | sed '/^$/d'
    rm -f "$out"
}

# 白名单静态池：先填临时集合，条数达标才 swap；DNS 全挂时保留旧集合
fill_whitelist_static() {
    local base=$1 family=$2; shift 2
    local ips=("$@") tmp="${base}_tmp" n want rr
    if [ "$family" = inet6 ]; then rr="AAAA"; else rr="A"; fi
    ipset create "$tmp" hash:net family "$family" -exist 2>/dev/null
    ipset flush "$tmp" 2>/dev/null
    for ip in "${ips[@]}"; do
        [ -n "$ip" ] && ipset add "$tmp" "$ip" -exist 2>/dev/null
    done
    while read -r ip; do
        [ -n "$ip" ] && ipset add "$tmp" "$ip" -exist 2>/dev/null
    done < <(resolve_whitelist "$rr")
    n=$(ipset list "$tmp" 2>/dev/null | grep -cE '^[0-9a-fA-F:.]+(/[0-9]+)?$')
    want=$(( ${#ips[@]} + 10 ))
    ipset create "$base" hash:net family "$family" -exist 2>/dev/null
    if [ "${n:-0}" -ge "$want" ]; then
        ipset swap "$tmp" "$base" >/dev/null 2>&1 && ipset destroy "$tmp" 2>/dev/null
        log "白名单静态池($family) 更新 ${n} 条"
    else
        ipset destroy "$tmp" 2>/dev/null
        log "白名单解析条数不足(${n}/${want})，沿用旧集合($family)"
    fi
    return 0
}

# 动态池：dnsmasq 只加不减，集合必须自带默认超时（2h），否则 IP 换主后永久豁免
ensure_dynamic_set() {
    local name=$1 family=$2
    if ipset list -n 2>/dev/null | grep -qx "$name"; then
        if ! ipset list -t "$name" 2>/dev/null | grep -q "timeout 7200"; then
            # ipset 被 iptables 引用时无法 destroy（in use by a kernel component），
            # 先把自有链清空解引用，apply_firewall 之后会整链重建
            iptables -F "$CH_GUARD" 2>/dev/null; iptables -F "$CH_GUARD_OUT" 2>/dev/null; iptables -F "$CH_GUARD_IN" 2>/dev/null
            if have_v6; then
                ip6tables -F "$CH_GUARD" 2>/dev/null; ip6tables -F "$CH_GUARD_OUT" 2>/dev/null; ip6tables -F "$CH_GUARD_IN" 2>/dev/null
            fi
            if ipset destroy "$name" 2>/dev/null && \
               ipset create "$name" hash:net family "$family" timeout 7200 >/dev/null 2>&1; then
                log "动态白名单池 $name 已重建为带 2h 超时"
            else
                log "⚠ 动态白名单池 $name 重建失败（沿用旧集合，条目无超时）"
            fi
        fi
    else
        ipset create "$name" hash:net family "$family" timeout 7200 >/dev/null 2>&1 || true
    fi
    return 0
}

sync_ipsets() {
    # 先清残留：旧版直接写在 FORWARD/OUTPUT 的 ipset 规则会让 destroy 永远失败
    cleanup_legacy_rules
    ipset create cnip hash:net 2>/dev/null || ipset flush cnip
    [ -s "$CNIP_LIST" ] && ipset restore -exist < "$CNIP_LIST" 2>/dev/null || true

    ensure_dynamic_set whitelist_ips_dynamic inet
    fill_whitelist_static whitelist_ips_static inet "${WHITELIST_IPS[@]}"

    if have_v6; then
        ipset create cnip6 hash:net family inet6 2>/dev/null || ipset flush cnip6 2>/dev/null
        [ -s "$CNIP6_LIST" ] && ipset restore -exist < "$CNIP6_LIST" 2>/dev/null || true
        ensure_dynamic_set whitelist_ips_dynamic6 inet6
        fill_whitelist_static whitelist_ips_static6 inet6 "${WHITELIST_IPS6[@]}"
    fi
    return 0
}

# 定位目标池：解析到临时集合，有结果才 swap（全部失败则保留旧集合）
refresh_geo_ipset() {
    local family=$1 set=$2 tmp="${2}_tmp" rr f4
    if [ "$family" = inet6 ]; then rr="AAAA"; f4="inet6"; else rr="A"; f4="inet"; fi
    ipset create "$tmp" hash:ip family "$f4" maxelem 65536 -exist 2>/dev/null
    ipset flush "$tmp" 2>/dev/null
    local out d r
    out=$(mktemp)
    for d in $GEO_DOMAINS; do
        for r in $GEO_RESOLVERS; do
            ( dig +short +time=1 +tries=1 "@$r" "$rr" "$d" 2>/dev/null \
                | grep -E '^[0-9a-fA-F:.]+$' >> "$out" ) &
        done
    done
    wait
    if [ -s "$out" ]; then
        sort -u "$out" | while read -r ip; do
            [ -n "$ip" ] && ipset add "$tmp" "$ip" -exist 2>/dev/null
        done
    fi
    rm -f "$out"
    local cnt
    cnt=$(ipset list "$tmp" 2>/dev/null | grep -cE '^[0-9a-fA-F:.]+(/[0-9]+)?$')
    if [ "${cnt:-0}" -gt 0 ]; then
        ipset create "$set" hash:ip family "$f4" maxelem 65536 -exist 2>/dev/null
        ipset swap "$tmp" "$set" >/dev/null 2>&1 && ipset destroy "$tmp" 2>/dev/null
    else
        ipset destroy "$tmp" 2>/dev/null
        ipset create "$set" hash:ip family "$f4" maxelem 65536 -exist 2>/dev/null
        log "定位目标池($family) 解析全部失败，沿用旧集合"
    fi
    return 0
}

have_xt_string() { iptables -m string --help 2>&1 | grep -q -- "--algo"; }

# 重建单个自有链（链内替换，不碰系统链）
# $1=iptables|ip6tables  $2=链名  $3=作用域  $4=cnip 集合  $5/$6=白名单池  $7=定位池
fill_chain() {
    local IPT=$1 ch=$2 scope=$3 set_cnip=$4 set_dyn=$5 set_static=$6 set_geo=$7 d iif=""
    # ip6tables 的 REJECT 类型名与 v4 不同，写错会静默失败、v6 拦截整块失效
    local RT="icmp-port-unreachable"
    [ "$IPT" = "ip6tables" ] && RT="icmp6-port-unreachable"
    $IPT -F "$ch" 2>/dev/null || return 0

    # ① 防送中 SNI 熔断（最优先；只做 443，定位上报不走明文 HTTP）
    if have_xt_string && [ "$scope" != "in" ]; then
        for d in $GEO_SNI_DOMAINS; do
            $IPT -A "$ch" -p tcp --dport 443 -m string --string "$d" --algo bm -j REJECT --reject-with tcp-reset 2>/dev/null
        done
    fi

    # ② 防送中 独立 IP 定位端点
    if [ "$scope" != "in" ]; then
        $IPT -A "$ch" -m set --match-set "$set_geo" dst -p tcp -j REJECT --reject-with tcp-reset 2>/dev/null
        $IPT -A "$ch" -m set --match-set "$set_geo" dst -j REJECT --reject-with "$RT" 2>/dev/null
    fi

    # ③ 测速类白名单（优先于 CN 拦截）
    $IPT -A "$ch" -m set --match-set "$set_dyn" dst -j ACCEPT 2>/dev/null
    $IPT -A "$ch" -m set --match-set "$set_static" dst -j ACCEPT 2>/dev/null

    # ④ .cn DNS 拦截（forward/in 限定 incusbr0，out 不限接口）
    if have_xt_string; then
        if [ "$scope" = "forward" ] || [ "$scope" = "in" ]; then
            iif="-i incusbr0"
        fi
        $IPT -A "$ch" $iif -p tcp --dport 53 -m string --hex-string "|02636e00|" --algo bm -j REJECT --reject-with "$RT" 2>/dev/null
        $IPT -A "$ch" $iif -p udp --dport 53 -m string --hex-string "|02636e00|" --algo bm -j REJECT --reject-with "$RT" 2>/dev/null
        $IPT -A "$ch" $iif -p tcp --dport 53 -m string --hex-string "|02434e00|" --algo bm -j REJECT --reject-with "$RT" 2>/dev/null
        $IPT -A "$ch" $iif -p udp --dport 53 -m string --hex-string "|02434e00|" --algo bm -j REJECT --reject-with "$RT" 2>/dev/null
    fi

    if [ "$scope" = "forward" ]; then
        # ⑤ 容器出站高危端口
        [ -n "$BLOCK_OUT_PORTS" ] && \
            $IPT -A "$ch" -i incusbr0 -p tcp -m multiport --dports "$BLOCK_OUT_PORTS" -j REJECT --reject-with "$RT" 2>/dev/null
        # ⑥ 回程放行：大陆客户端打进来的会话，容器回包是 conntrack ESTABLISHED。
        #    排在最前既省匹配开销，也把「CN 拦截只看 NEW / SYN 首包」这层语义钉死：
        #    改这里的人不能把整段 UDP 一起 REJECT，否则入站节点的回包会全灭。
        $IPT -A "$ch" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        # ⑦ 拦截去往 CN 的新连接：TCP 认 SYN、UDP 认 NEW，都不碰已建立会话的回包
        $IPT -A "$ch" -i incusbr0 -m set --match-set "$set_cnip" dst -p tcp --syn -j REJECT --reject-with "$RT" 2>/dev/null
        $IPT -A "$ch" -i incusbr0 -m set --match-set "$set_cnip" dst -p udp -m conntrack --ctstate NEW -j REJECT --reject-with "$RT" 2>/dev/null
        # ⑧ 兜底放行
        $IPT -A "$ch" -i incusbr0 -j ACCEPT 2>/dev/null
        $IPT -A "$ch" -o incusbr0 -j ACCEPT 2>/dev/null
    elif [ "$scope" = "out" ]; then
        # ⑥ 回程放行（宿主自己发起的会话同理）：ESTABLISHED,RELATED 不受 CN 拦截影响
        $IPT -A "$ch" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
        # ⑦ 宿主自身 → CN 的新连接
        $IPT -A "$ch" -m set --match-set "$set_cnip" dst -p tcp --syn -j REJECT --reject-with "$RT" 2>/dev/null
        $IPT -A "$ch" -m set --match-set "$set_cnip" dst -p udp -m conntrack --ctstate NEW -j REJECT --reject-with "$RT" 2>/dev/null
    fi
    return 0
}

ensure_top() {
    local IPT=$1 chain=$2 target=$3 idx
    if ! $IPT -C "$chain" -j "$target" 2>/dev/null; then
        $IPT -I "$chain" 1 -j "$target" 2>/dev/null && log "挂载 $target -> $chain"
        return 0
    fi
    idx=$($IPT -L "$chain" --line-numbers -n 2>/dev/null | awk -v t="$target" '$2==t{print $1; exit}')
    if [ "${idx:-0}" != "1" ]; then
        $IPT -D "$chain" -j "$target" 2>/dev/null
        $IPT -I "$chain" 1 -j "$target" 2>/dev/null
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

    cleanup_legacy_dns_hijack

    fill_chain iptables "$CH_GUARD"     forward cnip whitelist_ips_dynamic whitelist_ips_static "$IPSET_GEO4"
    fill_chain iptables "$CH_GUARD_OUT" out     cnip whitelist_ips_dynamic whitelist_ips_static "$IPSET_GEO4"
    fill_chain iptables "$CH_GUARD_IN"  in      cnip whitelist_ips_dynamic whitelist_ips_static "$IPSET_GEO4"

    ensure_top iptables FORWARD "$CH_GUARD"
    ensure_top iptables OUTPUT  "$CH_GUARD_OUT"
    ensure_top iptables INPUT   "$CH_GUARD_IN"

    # 容器走 IPv6 可以绕过 v4 的 CN 拦截和防送中，必须同样处理
    if have_v6; then
        ip6tables -N "$CH_GUARD"     2>/dev/null || true
        ip6tables -N "$CH_GUARD_OUT" 2>/dev/null || true
        ip6tables -N "$CH_GUARD_IN"  2>/dev/null || true

        fill_chain ip6tables "$CH_GUARD"     forward cnip6 whitelist_ips_dynamic6 whitelist_ips_static6 "$IPSET_GEO6"
        fill_chain ip6tables "$CH_GUARD_OUT" out     cnip6 whitelist_ips_dynamic6 whitelist_ips_static6 "$IPSET_GEO6"
        fill_chain ip6tables "$CH_GUARD_IN"  in      cnip6 whitelist_ips_dynamic6 whitelist_ips_static6 "$IPSET_GEO6"

        ensure_top ip6tables FORWARD "$CH_GUARD"
        ensure_top ip6tables OUTPUT  "$CH_GUARD_OUT"
        ensure_top ip6tables INPUT   "$CH_GUARD_IN"
    fi
    return 0
}

self_check() {
    local bad="" n udp_cnip est_ln cn_ln
    iptables -C FORWARD -j "$CH_GUARD"     2>/dev/null || bad="$bad FORWARD跳转"
    iptables -C OUTPUT  -j "$CH_GUARD_OUT" 2>/dev/null || bad="$bad OUTPUT跳转"
    iptables -C INPUT   -j "$CH_GUARD_IN"  2>/dev/null || bad="$bad INPUT跳转"
    ipset list -n 2>/dev/null | grep -qx cnip || bad="$bad CN网段"
    ipset list -n 2>/dev/null | grep -qx "$IPSET_GEO4" || bad="$bad 定位池"
    ipset list -n 2>/dev/null | grep -qx whitelist_ips_static || bad="$bad 白名单池"
    iptables -S "$CH_GUARD" 2>/dev/null | grep -q -- "$IPSET_GEO4" || bad="$bad 防送中规则"
    # 这些规则插入失败时是静默的，必须显式核对是否真的进了链
    iptables -S "$CH_GUARD" 2>/dev/null | grep -q -- "match-set cnip dst" || bad="$bad CN拦截规则"
    iptables -S "$CH_GUARD" 2>/dev/null | grep -q -- "match-set whitelist_ips_static" || bad="$bad 白名单规则"
    # UDP 拦截必须带 conntrack 状态，否则大陆入站会话的回包会被一起打掉（= UDP 全禁）
    udp_cnip=$(iptables -S "$CH_GUARD" 2>/dev/null | grep -- "match-set cnip dst" | grep -- " -p udp ")
    if [ -z "$udp_cnip" ]; then
        bad="$bad UDP拦截规则"
    elif ! printf '%s\n' "$udp_cnip" | grep -q "ctstate"; then
        bad="$bad UDP拦截无状态(会连回包一起禁)"
    fi
    # 回程放行必须排在 CN 拦截之前：语义上 CN 拦截只该看首包，顺序反了就是「先拦后放」，
    # 后来改规则的人很容易顺手把回包一起禁掉
    est_ln=$(iptables -S "$CH_GUARD" 2>/dev/null | grep -n "ESTABLISHED" | head -1 | cut -d: -f1)
    cn_ln=$(iptables -S "$CH_GUARD" 2>/dev/null | grep -n -- "match-set cnip dst" | head -1 | cut -d: -f1)
    if [ -z "${est_ln:-}" ]; then
        bad="$bad 回程放行规则"
    elif [ -n "${cn_ln:-}" ] && [ "${est_ln:-0}" -gt "${cn_ln:-0}" ]; then
        bad="$bad 回程放行晚于CN拦截"
    fi
    n=$(iptables -t nat -S OUTPUT 2>/dev/null | grep -c "$HOST_DNS_PORT" || true)
    [ "${n:-0}" -ne 0 ] && bad="$bad 旧53劫持残留"

    if have_v6; then
        ip6tables -C FORWARD -j "$CH_GUARD" 2>/dev/null || bad="$bad v6-FORWARD跳转"
        ip6tables -C OUTPUT  -j "$CH_GUARD_OUT" 2>/dev/null || bad="$bad v6-OUTPUT跳转"
        ipset list -n 2>/dev/null | grep -qx cnip6 || bad="$bad v6-CN网段"
        ip6tables -S "$CH_GUARD" 2>/dev/null | grep -q -- "match-set cnip6 dst" || bad="$bad v6-CN拦截规则"
    fi

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

# ============ 重装镜像选择（v6.2.0）============
# 优先级：容器自己的基础镜像（本地有）→ 同发行版的本地镜像 → 都没有就拒绝处置。
# 绝不再回退到 images:<distro>/latest：那个别名不存在，rebuild 会先停容器再取镜像失败。
pick_image() {
    local project=$1 c=$2 os fp cand
    fp=$(incus config get "$c" volatile.base_image --project "$project" 2>/dev/null || true)
    if [ -n "$fp" ] && incus image list local: -f csv -c f 2>/dev/null | grep -qx "$fp"; then
        echo "local:$fp"; return 0
    fi
    os=$(incus config get "$c" image.os --project "$project" 2>/dev/null || true)
    [ -z "$os" ] && return 1
    cand=$(incus image list local: -f csv -c fd 2>/dev/null | grep -i -- "$os" | head -n1 | cut -d, -f1)
    [ -n "$cand" ] && { echo "local:$cand"; return 0; }
    return 1
}

warn_no_image() {
    echo "   ↳ ⚠ 本机没有可用的本地镜像，命中违规将无法处置"
    echo "   ↳ ⚠ 先执行：incus image copy images:alpine/3.22 local: --alias guard-alpine"
}

# ============ 重装后系统级初始化（v6.2.9）============
# 巡检的 rebuild 是「裸装镜像」：openssh 没装、sshd 没进运行级，客户原有的 root
# 密码也随镜像一起消失 —— 容器变成谁也登不进去的空壳，SSH 和面板 WebSSH 全废
# （2026-11-19 的 u3031-g3qqd9tw 就是这样，空了 5 天没人发现）。
# 面板自己的「重装系统」建好后会跑一遍初始化，巡检不走那条路，所以这里补上同一套
# 系统级初始化：装 openssh → 生成 host key → 写 sshd_config → sshd 进 default 运行级
# 并启动；并把重装【之前】抓到的 root 密码散列原样写回（只经 stdin，不进 argv、不进日志）。
# 与面板唯一的有意差异：sshd_config 里 PasswordAuthentication 用 yes，否则客户拿
# 面板显示的密码根本登不进来（面板那套靠重装时注入公钥，巡检这边拿不到公钥）。
# 只做系统级初始化，不装面板/节点软件；公钥需客户在面板重装一次才会注入。
GUARD_SSH_PASSWORD_AUTH="yes"

_cap_access() {  # $1 project $2 container → 重装前的 root 密码散列（取不到就空）
    local project=$1 c=$2 h
    h=$(timeout 30 incus exec --project "$project" "$c" -- sh -c 'grep "^root:" /etc/shadow 2>/dev/null | cut -d: -f2 | head -n1' < /dev/null 2>/dev/null)
    printf '%s\n' "${h:-}"
}

_post_rebuild_init() {  # $1 project $2 container $3 重装前的 root 密码散列 → echo 一行结果
    local project=$1 c=$2 ph=$3 out="" i pw="未恢复" note
    for i in 1 2 3; do
        out=$(timeout 90 incus exec --project "$project" "$c" \
            --env PA="$GUARD_SSH_PASSWORD_AUTH" -- sh -c '
            if [ -f /etc/alpine-release ]; then
                for t in 1 2 3 4 5; do apk update >/dev/null 2>&1 && break; sleep 2; done
                apk add --no-cache openssh >/dev/null 2>&1 || apk add --no-cache openssh || exit 3
                ssh-keygen -A >/dev/null 2>&1
                printf "%s\n" "Include /etc/ssh/sshd_config.d/*.conf" "PasswordAuthentication ${PA:-yes}" "PermitRootLogin yes" "Subsystem sftp internal-sftp" > /etc/ssh/sshd_config
                chmod 644 /etc/ssh/sshd_config
                rc-update add sshd default >/dev/null 2>&1
                rc-service sshd restart >/dev/null 2>&1 || rc-service sshd start >/dev/null 2>&1
            else
                export DEBIAN_FRONTEND=noninteractive
                for t in 1 2 3 4 5; do apt-get update >/dev/null 2>&1 && break; sleep 3; done
                apt-get install -y openssh-server >/dev/null 2>&1 || exit 3
                ssh-keygen -A >/dev/null 2>&1
                printf "%s\n" "PasswordAuthentication ${PA:-yes}" "PermitRootLogin yes" >> /etc/ssh/sshd_config
                systemctl enable ssh >/dev/null 2>&1
                systemctl restart ssh >/dev/null 2>&1
            fi
            ls /etc/ssh/ssh_host_*_key >/dev/null 2>&1 || { echo INIT_NOHOSTKEY; exit 0; }
            if grep -l "^sshd$" /proc/*/comm 2>/dev/null | head -n1 >/dev/null; then echo INIT_OK; else echo INIT_NOSSHD; fi
        ' < /dev/null 2>&1 | tail -n1) || out=""
        case "$out" in INIT_OK) break;; esac
        sleep 3
    done
    case "$out" in
        INIT_OK)        note="✅ openssh 已装、sshd 已启用";;
        INIT_NOHOSTKEY) note="⚠ sshd 起来了但 host key 缺失";;
        INIT_NOSSHD)    note="⚠ openssh 装了但 sshd 没在跑";;
        *)              note="❌ 初始化失败（apk/apt 或容器网络问题，需人工介入）";;
    esac
    # 回写重装前的 root 密码散列：只走 stdin，不进 argv、不进日志
    if [ -n "$ph" ] && [ "$ph" != "*" ] && [ "$ph" != "!" ]; then
        if printf 'root:%s\n' "$ph" | timeout 60 incus exec --project "$project" "$c" -- chpasswd -e >/dev/null 2>&1; then
            pw="已恢复"
        else
            pw="回写失败"
        fi
    fi
    echo "$note（root 密码:$pw，节点软件未装；公钥需客户在面板重装一次才注入）"
}

# =======================================================================
case "$MODE" in
    apply|full)
        ensure_deps
        sync_cnip
        sync_ipsets
        [ "$MODE" = "full" ] && sync_incus_dnsmasq
        refresh_geo_ipset inet  "$IPSET_GEO4"
        have_v6 && refresh_geo_ipset inet6 "$IPSET_GEO6"
        ensure_conntrack_tuning
        apply_firewall
        if ! self_check; then
            exit 1
        fi
        log "防火墙 + CN 拦截 + 防送中规则已应用（白名单 $(uniq_wl_domains | wc -l) 个域名，v4+v6；UDP 仅拦 NEW 首包，回包按 ESTABLISHED 放行）"
        [ "$MODE" = "apply" ] && exit 0
        ;;
    scan)
        log "scan-only：跳过防火墙重建"
        ;;
esac

ensure_wrapper

command -v incus >/dev/null 2>&1 || { log "未发现 incus，跳过容器扫描"; exit 0; }
if ! incus image list local: -f csv -c f 2>/dev/null | grep -q .; then
    echo "⚠ 本机无本地镜像：一旦命中违规将无法处置，请先 incus image copy images:alpine/3.22 local: --alias guard-alpine"
fi

PROJECT_LIST=$(incus project list -f csv -c n 2>/dev/null)
[ -z "$PROJECT_LIST" ] && PROJECT_LIST="default"

COUNT=0
HIT=0
SKIP=0
UNSCANNED=0

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
                KW_LONG="$KL"; KW_BIN="$(echo $KB | tr " " "|")"
                [ -f /proc/net/tcp ] || { echo "SCAN_UNAVAILABLE"; exit 0; }
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

                    # 只看每个参数的文件名部分与可执行文件名：
                    # 剥掉目录与 --key=value 的前缀，并跳过配置文件类后缀，
                    # 这样 /etc/prometheus/x.yml、--config=/opt/grafana/y.json 不再误伤
                    BASE=$(printf "%s\n" "$TXT" | while IFS= read -r t; do
                        t="${t##*=}"; t="${t##*/}"
                        case "$t" in
                            *.yml|*.yaml|*.conf|*.json|*.log|*.txt|*.md|*.html|*.xml|*.ini|*.toml|*.properties|*.pid|*.lock|"") continue ;;
                        esac
                        printf "%s\n" "$t"
                    done)
                    BIN=$(readlink /proc/$p/exe 2>/dev/null)
                    [ -n "$BIN" ] && BASE="$BASE
${BIN##*/}"

                    M=$(printf "%s\n" "$BASE" | grep -oiE "$KW_LONG" | head -n1)
                    [ -n "$M" ] && { echo "违规进程: $M"; exit 0; }

                    M2=$(printf "%s\n" "$BASE" | grep -xE "$KW_BIN" | head -n1)
                    [ -n "$M2" ] && { echo "违规进程: $M2"; exit 0; }
                done

                for f in /opt/nezha/agent/nezha-agent /usr/local/bin/nezha-agent /usr/local/bin/nezha_agent /root/nezha-agent /etc/init.d/nezha-agent /etc/systemd/system/nezha-agent.service; do
                    [ -e "$f" ] && { echo "残留文件: $f"; exit 0; }
                done
                exit 0
            ' < /dev/null 2>/dev/null)
        EXEC_RC=$?

        if [ "$HIT_REASON" = "SCAN_UNAVAILABLE" ]; then
            UNSCANNED=$((UNSCANNED+1))
            echo "[⚠ 未扫描] 容器内没有 /proc/net/tcp"
            continue
        fi
        if [ -z "$HIT_REASON" ] && [ "$EXEC_RC" -ne 0 ]; then
            UNSCANNED=$((UNSCANNED+1))
            echo "[⚠ 未扫描] incus exec 失败或超时（rc=$EXEC_RC）"
            continue
        fi

        if [ -n "$HIT_REASON" ]; then
            HIT=$((HIT+1))
            echo "【🚨 违规: $HIT_REASON】"
            if [ "$MODE" = "scan" ]; then
                echo "   ↳ (scan-only，未执行重装)"
                continue
            fi
            if ! TARGET_IMAGE=$(pick_image "$project" "$c"); then
                SKIP=$((SKIP+1))
                warn_no_image
                echo "   ↳ ❌ 拒绝处置：找不到匹配的本地镜像（容器 OS: $(incus config get "$c" image.os --project "$project" 2>/dev/null)）"
                continue
            fi
            echo "   ↳ 🔄 强制执行抹除性重装自愈（镜像 $TARGET_IMAGE）..."
            PRE_HASH=$(_cap_access "$project" "$c")
            RB_OUT=$(timeout 300 incus rebuild --project "$project" "$TARGET_IMAGE" "$c" --force < /dev/null 2>&1)
            RB_RC=$?
            if [ "$RB_RC" -eq 0 ]; then
                ST=$(incus list --project "$project" "$c" -f csv -c s 2>/dev/null)
                if [ "$ST" != "RUNNING" ]; then
                    incus start --project "$project" "$c" >/dev/null 2>&1
                    sleep 3
                    ST=$(incus list --project "$project" "$c" -f csv -c s 2>/dev/null)
                fi
                if [ "$ST" = "RUNNING" ]; then
                    echo "   ↳ ✅ 重装成功，容器已恢复运行"
                    echo "   ↳ 🧰 系统初始化：$(_post_rebuild_init "$project" "$c" "$PRE_HASH")"
                else
                    echo "   ↳ ❌ FATAL 重装返回成功但容器状态为 ${ST:-未知}，需人工介入"
                fi
            else
                echo "   ↳ ❌ FATAL 重装失败 rc=$RB_RC：$(printf '%s' "$RB_OUT" | tail -n 2 | tr '\n' ' ' | cut -c1-300)"
            fi
        else
            echo "[✔ 正常]"
        fi
    done
done

echo "------------------------------------------------"
log "巡检结束：盘查 ${COUNT} 台，命中 ${HIT} 台，未扫描 ${UNSCANNED} 台，拒绝处置 ${SKIP} 台"