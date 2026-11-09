#!/bin/bash
# =======================================================================
# Incus 宿主网络安全一体化部署脚本 v6.1.1
#   1) 装依赖（失败才动镜像源，成功绝不动）
#   2) 写唯一名单 whitelist.conf（incus.sh 直接 source，不再各写一份）
#   3) 生成定时执行体 wrapper（flock、远端更新、sha256 pin、退出码告警）
#   4) 备份现有防火墙规则 + 立即应用一次（含防送中）
# 与 v6.0.0 差异：
#   - 去掉宿主 53 劫持与宿主 dnsmasq 配置：容器的 DNS 由 incusbr0 自带 dnsmasq 负责，
#     宿主 CN 拦截按 IP 网段做，不再有「dnsmasq 挂了宿主 DNS 全废」的故障点
#   - 名单单一来源 whitelist.conf，补齐测速/延迟检测域名
#   - crontab 写入前校验读回，读失败直接中止（不再可能清空别人的 cron）
#   - 应用前保存 iptables 快照（保留 3 份）、加 logrotate、加 --uninstall
#   - wrapper 透传参数（--apply-only 终于有效）、默认远端更新、超时 240s
# 用法：bash incus-cron.sh [--apply-only|--scan-only|--uninstall|--pin]
# =======================================================================

set -uo pipefail

CONF_DIR="/etc/iptables-custom"
INIT_SCRIPT="${CONF_DIR}/init.sh"
GUARD_CONF="${CONF_DIR}/whitelist.conf"
WRAPPER="/usr/local/bin/incus_cron.sh"
WRAPPER_VERSION="5"
LOG_FILE="/var/log/incus_clean.log"
REMOTE_URL="https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh"
CNIP_URL="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/cn/ipv4-aggregated.txt"

# 远端脚本的 sha256 pin：留空 = 跟随 main 分支；填了就只执行哈希匹配的版本。
# 用 --pin 参数可在部署时把 pin 锁成「当前安装的这一份」。
PIN_SHA256=""
PIN_MODE=0

# ============ 名单（唯一来源，写入 whitelist.conf）============
# 域名按后缀匹配，写 speedtest.net 即覆盖 *.speedtest.net
WHITELIST_DOMAINS=(
    # —— 测速：Ookla / Speedtest
    "speedtest.net" "ookla.com" "ooklaserver.net" "speedtestcustom.com"
    # —— 测速：Netflix fast.com
    "fast.com" "nflxvideo.net" "nflximg.net" "nflxext.net" "nflxso.net"
    # —— 测速：Cloudflare
    "cloudflare.com" "one.one.one.one"
    # —— 测速：其它常见站
    "openspeedtest.com" "librespeed.org" "speedof.me" "testmy.net"
    "bandwidthplace.com" "nperf.com" "waveform.com" "speedcheck.org"
    # —— 连通性 / 延迟检测
    "captive.apple.com" "gstatic.com" "clients3.google.com" "clients4.google.com"
    "msftconnecttest.com" "msftncsi.com" "detectportal.firefox.com"
    "connectivity-check.ubuntu.com"
    "ping.pe" "ping.sx" "ping0.cc"
    # —— IP 检测 / 出口查询
    "ip.sb" "ipinfo.io" "ip-api.com" "ipwho.is" "ifconfig.me" "icanhazip.com"
    "checkip.amazonaws.com"
    # —— Apple 内容 CDN（存量）
    "zstaticcdn.com"
)

WHITELIST_IPS=(
    "1.1.1.1" "1.0.0.1" "8.8.8.8" "8.8.4.4" "9.9.9.9" "208.67.222.222"
)

BLACKLIST_DOMAINS=(
    "baidu.com" "taobao.com" "qq.com" "jd.com" "bilibili.com" "163.com"
    "weibo.com" "zhihu.com" "douyin.com" "kuaishou.com" "alipay.com"
    "alibaba.com" "tencent.com" "sohu.com" "sina.com" "360.com"
    "iqiyi.com" "youku.com" "xiaohongshu.com" "pinduoduo.com"
    "meituan.com" "ele.me" "aliyun.com"
)

BLOCK_OUT_PORTS="22,23,445,3389,6379,2375,2376"

log() { echo "[$(date '+%F %T')] $*"; }

[ "$(id -u)" -eq 0 ] || { echo "必须以 root 运行"; exit 1; }

ACTION="deploy"
case "${1:-}" in
    --apply-only) ACTION="apply" ;;
    --scan-only)  ACTION="scan" ;;
    --uninstall)  ACTION="uninstall" ;;
    --pin)        ACTION="deploy"; PIN_MODE=1 ;;
    "")           ACTION="deploy" ;;
    *)            echo "未知参数：$1"; exit 2 ;;
esac

# ================================================================ 卸载
do_uninstall() {
    log "开始卸载 incus-guard..."
    local tmp ch
    tmp=$(mktemp)
    if crontab -l > "$tmp" 2>/dev/null; then
        grep -v "incus_cron.sh" "$tmp" | crontab - || log "⚠ crontab 回写失败"
        log "已移除 crontab 条目"
    fi
    rm -f "$tmp"

    for ch in INCUS_GUARD INCUS_GUARD_OUT INCUS_GUARD_IN; do
        iptables -D FORWARD -j "$ch" 2>/dev/null
        iptables -D OUTPUT  -j "$ch" 2>/dev/null
        iptables -D INPUT   -j "$ch" 2>/dev/null
        iptables -F "$ch" 2>/dev/null
        iptables -X "$ch" 2>/dev/null
    done
    iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null
    iptables -t nat -D OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53535 2>/dev/null
    ipset destroy cnip 2>/dev/null
    ipset destroy geo_v4 2>/dev/null
    ipset destroy whitelist_ips_static 2>/dev/null
    ipset destroy whitelist_ips_dynamic 2>/dev/null

    systemctl disable --now custom-firewall.service >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/custom-firewall.service
    systemctl daemon-reload >/dev/null 2>&1 || true

    rm -f "$WRAPPER" "$INIT_SCRIPT"
    rm -rf /usr/local/lib/incus-guard
    rm -f /etc/logrotate.d/incus-guard
    # 保留 snapshot-*.rules 便于回滚，其余配置清掉
    find "$CONF_DIR" -maxdepth 1 -type f ! -name 'snapshot-*.rules' -delete 2>/dev/null

    log "卸载完成。历史规则快照保留在 ${CONF_DIR}/snapshot-*.rules"
    log "如需恢复：iptables-restore < ${CONF_DIR}/snapshot-<时间戳>.rules"
}

if [ "$ACTION" = "uninstall" ]; then
    do_uninstall
    exit 0
fi

# ================================================================ 依赖
export DEBIAN_FRONTEND=noninteractive
PKGS="ipset iptables dnsutils curl cron util-linux"

fix_apt_mirror() {
    local OS_TYPE="ubuntu" ARCH f official regex
    ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        [ "${ID:-}" = "debian" ] && OS_TYPE="debian"
    fi
    if [ "$OS_TYPE" = "debian" ]; then
        official="http://deb.debian.org/debian/"
        regex="s#https?://[^/]*(aliyun|tencent|tsinghua|ustc|huaweicloud)[^/]*/debian/?#${official}#g"
    else
        if [ "$ARCH" = "arm64" ]; then
            official="http://ports.ubuntu.com/ubuntu-ports/"
        else
            official="http://archive.ubuntu.com/ubuntu/"
        fi
        regex="s#https?://[^/]*(aliyun|tencent|tsinghua|ustc|huaweicloud)[^/]*/(ubuntu-ports|ubuntu)/?#${official}#g"
    fi
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [ -f "$f" ] || continue
        grep -qE "aliyun|tencent|tsinghua|ustc|huaweicloud" "$f" 2>/dev/null || continue
        cp -a "$f" "${f}.bak-incusguard" 2>/dev/null || true
        sed -i -E "$regex" "$f" 2>/dev/null || true
        log "镜像源已切回官方：$f（备份 ${f}.bak-incusguard）"
    done
}

pkg_install() {
    # 先按现状装；只有装失败才动镜像源，成功后重试一次
    apt-get update -yq >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    if apt-get install -yq -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" $PKGS >/dev/null 2>&1; then
        return 0
    fi
    log "依赖安装失败，切换官方镜像源后重试"
    fix_apt_mirror
    apt-get update -yq >/dev/null 2>&1 || true
    # shellcheck disable=SC2086
    apt-get install -yq -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" $PKGS >/dev/null 2>&1
}

pkg_install || log "⚠ 依赖安装未完全成功，继续尝试（缺什么会在运行时日志里报出来）"
systemctl enable --now cron >/dev/null 2>&1 || true

if ! command -v incus >/dev/null 2>&1; then
    log "⚠ 未检测到 incus 命令：本机可能不是 Incus 宿主，规则仍按 incusbr0 配置，请自行确认"
fi

# ================================================================ 名单单一来源
mkdir -p "$CONF_DIR"
{
    echo "# incus-guard 名单（唯一来源，incus.sh 会 source 本文件）"
    echo "# 生成时间：$(date '+%F %T')"
    echo "WHITELIST_DOMAINS=("
    printf '    "%s"\n' "${WHITELIST_DOMAINS[@]}"
    echo ")"
    echo "WHITELIST_IPS=("
    printf '    "%s"\n' "${WHITELIST_IPS[@]}"
    echo ")"
    echo "BLACKLIST_DOMAINS=("
    printf '    "%s"\n' "${BLACKLIST_DOMAINS[@]}"
    echo ")"
    echo "BLOCK_OUT_PORTS=\"$BLOCK_OUT_PORTS\""
} > "$GUARD_CONF"
log "名单已写入 $GUARD_CONF（白名单 $(printf '%s\n' "${WHITELIST_DOMAINS[@]}" | sed '/^$/d' | sort -u | wc -l) 个域名）"

# ================================================================ CN IP 库
TMP_IP=$(mktemp)
if curl -sLf --max-time 60 "$CNIP_URL" 2>/dev/null | tr -d '\r' | awk '/^[0-9]/ {print "add cnip " $1}' > "$TMP_IP"; then
    n=$(wc -l < "$TMP_IP")
    if [ "${n:-0}" -ge 1000 ]; then
        mv -f "$TMP_IP" "${CONF_DIR}/cnip.list"
        log "CN IP 库写入 ${n} 条"
    else
        log "CN IP 库条数异常(${n})，保留旧文件"
    fi
else
    log "CN IP 库拉取失败，保留旧文件"
fi
rm -f "$TMP_IP"

# ================================================================ 安装执行体
mkdir -p /usr/local/lib/incus-guard
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
if [ -f "${SRC_DIR}/incus.sh" ]; then
    install -m 755 "${SRC_DIR}/incus.sh" /usr/local/lib/incus-guard/incus.sh
    log "执行体已从本地目录安装"
elif curl -sLf --max-time 120 -o /usr/local/lib/incus-guard/incus.sh "$REMOTE_URL"; then
    chmod 755 /usr/local/lib/incus-guard/incus.sh
    log "执行体已从远端安装"
else
    echo "FATAL: 无法获得 incus.sh（本地无 ${SRC_DIR}/incus.sh，远端不可达）"
    exit 1
fi
bash -n /usr/local/lib/incus-guard/incus.sh || { echo "FATAL: incus.sh 语法错误"; exit 1; }
NEW_SHA=$(sha256sum /usr/local/lib/incus-guard/incus.sh | cut -d' ' -f1)
log "执行体 sha256=${NEW_SHA}"
[ "$PIN_MODE" = "1" ] && PIN_SHA256="$NEW_SHA"

# ================================================================ init.sh（开机复用）
cat > "$INIT_SCRIPT" <<'INIT'
#!/bin/bash
# 开机恢复：只应用防火墙，不扫描容器
LOCAL=/usr/local/lib/incus-guard/incus.sh
if [ -x "$LOCAL" ]; then
    exec "$LOCAL" --apply-only
fi
# 本地副本不存在时退回 wrapper（参数会原样透传）
exec /usr/local/bin/incus_cron.sh --apply-only
INIT
chmod 755 "$INIT_SCRIPT"

# ================================================================ wrapper
cat > "$WRAPPER" <<'WRAP'
#!/bin/bash
# Incus 巡检执行体 wrapper
#  - flock 防重入：上一轮没跑完，本轮直接跳过
#  - 参数原样透传给 incus.sh（--apply-only / --scan-only 都有效）
#  - 远端更新：拉取后先 bash -n，再按 PIN_SHA256 校验（pin 为空则跳过校验）
#  - 失败 / 超时 / 拉取异常一律写日志，不再静默
WRAPPER_VERSION="@V@"
LOG_FILE="/var/log/incus_clean.log"
LOCAL_DIR="/usr/local/lib/incus-guard"
LOCAL="$LOCAL_DIR/incus.sh"
LOCK="/run/incus_guard.lock"
URL="https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh"
PIN_SHA256="@P@"
# 远端更新开关：1 = 每轮拉远端并覆盖本地；0 = 只跑本地副本
ENABLE_REMOTE=1
MAX_SECONDS=240

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
mkdir -p "$LOCAL_DIR"

# 取脚本内 SCRIPT_VERSION（旧版没有这个变量，返回空）
ver_of() { grep -m1 '^SCRIPT_VERSION=' "$1" 2>/dev/null | cut -d'"' -f2; }

exec 9>"$LOCK"
flock -n 9 || { echo "[$(date '+%F %T')] 上一轮未结束，跳过本轮" >> "$LOG_FILE"; exit 0; }

TMP_OUT=$(mktemp); trap 'rm -f "$TMP_OUT" "$TMP_OUT.clean"' EXIT
START=$(date +%s)
RC_NOTE=""

if [ "$ENABLE_REMOTE" = "1" ]; then
    if ! curl -sLf --max-time 60 -H "Cache-Control: no-cache" -o "$LOCAL.tmp" "$URL"; then
        echo "[$(date '+%F %T')] ⚠ 拉取 incus.sh 失败（网络或仓库不可达），改用本地副本" >> "$LOG_FILE"
        rm -f "$LOCAL.tmp"
        RC_NOTE="拉取失败"
    elif ! bash -n "$LOCAL.tmp" 2>/dev/null; then
        echo "[$(date '+%F %T')] ⚠ 远端 incus.sh 语法错误，拒绝执行（沿用本地副本）" >> "$LOG_FILE"
        rm -f "$LOCAL.tmp"
        RC_NOTE="语法错误"
    elif [ -n "$(ver_of "$LOCAL")" ] && \
         [ "$(printf '%s\n%s\n' "$(ver_of "$LOCAL.tmp")" "$(ver_of "$LOCAL")" | sort -V | tail -n1)" = "$(ver_of "$LOCAL")" ] && \
         [ "$(ver_of "$LOCAL.tmp")" != "$(ver_of "$LOCAL")" ]; then
        echo "[$(date '+%F %T')] ⚠ 远端版本 $(ver_of "$LOCAL.tmp") 低于本地 $(ver_of "$LOCAL")，拒绝降级（CDN 缓存或误回退）" >> "$LOG_FILE"
        rm -f "$LOCAL.tmp"
        RC_NOTE="远端版本较低"
    elif [ -n "$PIN_SHA256" ] && ! echo "$PIN_SHA256  $LOCAL.tmp" | sha256sum -c - >/dev/null 2>&1; then
        echo "[$(date '+%F %T')] ⚠ 远端 sha256 与 pin 不符，拒绝执行（沿用本地副本）" >> "$LOG_FILE"
        rm -f "$LOCAL.tmp"
        RC_NOTE="pin 不符"
    else
        mv -f "$LOCAL.tmp" "$LOCAL"; chmod 755 "$LOCAL"
    fi
fi

[ -f "$LOCAL" ] || { echo "[$(date '+%F %T')] ⚠ 无可用 incus.sh，终止" >> "$LOG_FILE"; exit 1; }
chmod 755 "$LOCAL" 2>/dev/null || true

timeout "$MAX_SECONDS" bash "$LOCAL" "$@" > "$TMP_OUT" 2>&1
RC=$?
DUR=$(( $(date +%s) - START ))

sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$TMP_OUT" | sed -E 's/\r/\n/g' > "$TMP_OUT.clean"

# 事件入库
if grep -qE "违规:|重装成功|重装失败|FATAL" "$TMP_OUT.clean" 2>/dev/null; then
    if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 102400 ]; then
        tail -n 300 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv -f "${LOG_FILE}.tmp" "$LOG_FILE"
        echo "--- $(date '+%F %T') 日志超 100KB 已裁剪" >> "$LOG_FILE"
    fi
    echo "=== [$(date '+%F %T')] 🚨 巡检事件（rc=$RC 耗时=${DUR}s） ===" >> "$LOG_FILE"
    grep -E "违规:|重装成功|重装失败|FATAL" "$TMP_OUT.clean" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
fi

# 异常兜底：非零退出、超时、或明显过慢都要留痕
if [ "$RC" -ne 0 ] || [ "$DUR" -gt 200 ]; then
    echo "[$(date '+%F %T')] ⚠ 巡检异常 rc=$RC 耗时=${DUR}s ${RC_NOTE}" >> "$LOG_FILE"
    tail -n 20 "$TMP_OUT.clean" >> "$LOG_FILE" 2>/dev/null
fi

[ "$RC" -eq 0 ] && exit 0
exit 1
WRAP

sed -i "s/@V@/${WRAPPER_VERSION}/" "$WRAPPER"
if [ -n "$PIN_SHA256" ]; then
    sed -i "s/@P@/${PIN_SHA256}/" "$WRAPPER"
else
    sed -i 's/@P@//' "$WRAPPER"
fi

bash -n "$WRAPPER" || { echo "FATAL: wrapper 语法错误"; exit 1; }
chmod 755 "$WRAPPER"

# ================================================================ logrotate
cat > /etc/logrotate.d/incus-guard <<'LR'
/var/log/incus_clean.log {
    size 5M
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
LR

# ================================================================ systemd
cat > /etc/systemd/system/custom-firewall.service <<'SERVICE'
[Unit]
Description=Custom Outbound Firewall for Host and Incus Containers (incus-guard)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/etc/iptables-custom/init.sh
TimeoutStartSec=300

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable custom-firewall.service >/dev/null 2>&1 || true

# ================================================================ 防火墙快照（应用前）
if command -v iptables-save >/dev/null 2>&1; then
    SNAP="${CONF_DIR}/snapshot-$(date '+%F-%H%M%S').rules"
    iptables-save > "$SNAP" 2>/dev/null && log "已保存防火墙快照 $(basename "$SNAP")"
    ls -1t "${CONF_DIR}"/snapshot-*.rules 2>/dev/null | tail -n +4 | while read -r old; do rm -f "$old"; done
fi

# ================================================================ cron
CRON_TMP=$(mktemp); CRON_ERR=$(mktemp)
if crontab -l > "$CRON_TMP" 2> "$CRON_ERR"; then
    :
elif grep -qi "no crontab" "$CRON_ERR"; then
    : > "$CRON_TMP"
else
    echo "FATAL: 读取现有 crontab 失败，为避免清空其它任务已中止："
    cat "$CRON_ERR"
    rm -f "$CRON_TMP" "$CRON_ERR"
    exit 1
fi
{ grep -v "incus_cron.sh" "$CRON_TMP" || true; echo "*/5 * * * * $WRAPPER"; } \
    | grep -v '^$' | crontab - || { echo "FATAL: crontab 写入失败"; rm -f "$CRON_TMP" "$CRON_ERR"; exit 1; }
rm -f "$CRON_TMP" "$CRON_ERR"
if crontab -l 2>/dev/null | grep -q "incus_cron.sh"; then
    log "crontab 已写入（每 5 分钟）"
else
    echo "FATAL: crontab 写入后读回校验失败"
    exit 1
fi

# ================================================================ 立即应用
RUN_ARG=""
case "$ACTION" in
    apply) RUN_ARG="--apply-only" ;;
    scan)  RUN_ARG="--scan-only" ;;
esac

log "执行首轮..."
bash "$WRAPPER" $RUN_ARG
RC=$?
log "首轮结束 rc=$RC，最近日志："
tail -n 15 "$LOG_FILE" 2>/dev/null || true

echo "------------------------------------------------"
if [ "$RC" -eq 0 ]; then
    log "部署完成。"
else
    log "⚠ 部署已写入但首轮执行 rc=$RC，请查看 $LOG_FILE"
fi
log "  巡检：$WRAPPER（每 5 分钟，手动跑：$WRAPPER）"
log "  只应用防火墙：$WRAPPER --apply-only"
log "  只扫描不重装：$WRAPPER --scan-only"
log "  卸载：bash $0 --uninstall"
log "  日志：$LOG_FILE（logrotate 5M×4）"
log "  名单：$GUARD_CONF"
exit "$RC"