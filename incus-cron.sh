#!/bin/bash
# =======================================================================
# Incus 宿主网络安全一体化部署脚本 v6.0.0
#   1) 装依赖、写 dnsmasq / ipset / CN 库
#   2) 生成定时执行体 wrapper（带 flock、退出码告警、sha256 pin）
#   3) 立即应用一次防火墙（含防送中）
# 与旧版差异：
#   - 不再 rm /etc/resolv.conf（bind 挂载的机器上会 EBUSY 直接崩，且会覆盖厂商 DNS）
#   - 不再全局大扫除系统链，规则落在自有链 INCUS_GUARD/_OUT/_IN
#   - wrapper 带版本号，可在老机器上原地升级
# =======================================================================

set -uo pipefail

CONF_DIR="/etc/iptables-custom"
INIT_SCRIPT="${CONF_DIR}/init.sh"
WRAPPER="/usr/local/bin/incus_cron.sh"
WRAPPER_VERSION="3"
LOG_FILE="/var/log/incus_clean.log"
REMOTE_URL="https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh"
CNIP_URL="https://raw.githubusercontent.com/ipverse/country-ip-blocks/master/country/cn/ipv4-aggregated.txt"

# 固定的 incus.sh 校验值（发布时填入；留空则跳过校验并在日志里提示）
PIN_SHA256=""

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

BLOCK_OUT_PORTS="22,23,445,3389,6379,2375,2376"

log() { echo "[$(date '+%F %T')] $*"; }

[ "$(id -u)" -eq 0 ] || { echo "必须以 root 运行"; exit 1; }

# ---------------------------------------------------------------- 依赖
export DEBIAN_FRONTEND=noninteractive
apt-get update -yq || true
apt-get install -yq -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" \
    ipset iptables dnsutils curl cron util-linux || true
systemctl enable --now cron >/dev/null 2>&1 || true

# ---------------------------------------------------------------- apt 源（deb822 也覆盖）
OS_TYPE="ubuntu"; ARCH=$(dpkg --print-architecture 2>/dev/null || echo amd64)
if [ -f /etc/os-release ]; then
    . /etc/os-release
    [ "${ID:-}" = "debian" ] && OS_TYPE="debian"
fi
if [ "$OS_TYPE" = "debian" ]; then
    OFFICIAL_URL="http://deb.debian.org/debian/"
    MATCH_REGEX="s#https?://[^/]*(aliyun|tencent|tsinghua|ustc|huaweicloud)[^/]*/debian/?#${OFFICIAL_URL}#g"
else
    if [ "$ARCH" = "arm64" ]; then
        OFFICIAL_URL="http://ports.ubuntu.com/ubuntu-ports/"
    else
        OFFICIAL_URL="http://archive.ubuntu.com/ubuntu/"
    fi
    MATCH_REGEX="s#https?://[^/]*(aliyun|tencent|tsinghua|ustc|huaweicloud)[^/]*/(ubuntu-ports|ubuntu)/?#${OFFICIAL_URL}#g"
fi
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [ -f "$f" ] || continue
    grep -qE "aliyun|tencent|tsinghua|ustc|huaweicloud" "$f" 2>/dev/null || continue
    cp -a "$f" "${f}.bak-noanyloc" 2>/dev/null || true
    sed -i -E "${MATCH_REGEX}" "$f" 2>/dev/null || true
done

# ---------------------------------------------------------------- dnsmasq（宿主）
mkdir -p /etc/dnsmasq.d
if [ ! -f /etc/dnsmasq.conf ] || ! grep -q "conf-dir=/etc/dnsmasq.d/" /etc/dnsmasq.conf; then
    echo "conf-dir=/etc/dnsmasq.d/,*.conf" > /etc/dnsmasq.conf
fi

DNS_CONF="port=53535\nlisten-address=127.0.0.1\nbind-interfaces\n"
for d in "${WHITELIST_DOMAINS[@]}"; do
    c=$(echo "$d" | sed 's/^\*\.//')
    DNS_CONF="${DNS_CONF}ipset=/${c}/whitelist_ips_dynamic\n"
done
for d in "${BLACKLIST_DOMAINS[@]}"; do
    c=$(echo "$d" | sed 's/^\*\.//')
    DNS_CONF="${DNS_CONF}address=/${c}/0.0.0.0\n"
done
DNS_CONF="${DNS_CONF}server=8.8.8.8\nserver=1.1.1.1\n"
printf "$DNS_CONF" > /etc/dnsmasq.d/dynamic_whitelist.conf
systemctl restart dnsmasq >/dev/null 2>&1 || systemctl start dnsmasq >/dev/null 2>&1 || true
log "宿主 dnsmasq 已配置（127.0.0.1:53535）"

# 注意：不修改 /etc/resolv.conf。若该文件是 bind 挂载，rm 会 EBUSY；
# 且机票 runtime 依赖厂商 agent 写入的内容。

# ---------------------------------------------------------------- CN IP 库
mkdir -p "$CONF_DIR"
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

# ---------------------------------------------------------------- whitelist.conf
{
    echo "WHITELIST_DOMAINS=("
    printf '    "%s"\n' "${WHITELIST_DOMAINS[@]}"
    echo ")"
    echo "WHITELIST_IPS=("
    printf '    "%s"\n' "${WHITELIST_IPS[@]}"
    echo ")"
    echo "BLOCK_OUT_PORTS=\"$BLOCK_OUT_PORTS\""
} > "${CONF_DIR}/whitelist.conf"

# ---------------------------------------------------------------- incusbr0 DNS
if command -v incus >/dev/null 2>&1; then
    RAW=""
    for d in "${WHITELIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        RAW="${RAW}ipset=/${c}/whitelist_ips_dynamic\n"
    done
    for d in "${BLACKLIST_DOMAINS[@]}"; do
        c=$(echo "$d" | sed 's/^\*\.//')
        RAW="${RAW}address=/${c}/0.0.0.0\n"
    done
    printf "$RAW" | incus network set incusbr0 raw.dnsmasq=- >/dev/null 2>&1 || true
    incus network set incusbr0 security.acls.default.egress.action=allow  >/dev/null 2>&1 || true
    incus network set incusbr0 security.acls.default.ingress.action=allow >/dev/null 2>&1 || true
    log "incusbr0 raw.dnsmasq 已下发"
fi

# ---------------------------------------------------------------- 安装执行体
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

# ---------------------------------------------------------------- init.sh（开机复用）
cat > "$INIT_SCRIPT" <<'INIT'
#!/bin/bash
# 开机恢复：调用同目录下的执行体逻辑（不带 --scan-only，只应用防火墙）
LOCAL=/usr/local/lib/incus-guard/incus.sh
if [ -x "$LOCAL" ]; then
    exec "$LOCAL" --apply-only
fi
# 本地副本不存在时退回远端（含校验）
exec /usr/local/bin/incus_cron.sh --apply-only
INIT
chmod 755 "$INIT_SCRIPT"

# ---------------------------------------------------------------- wrapper
cat > "$WRAPPER" <<'WRAP'
#!/bin/bash
# Incus 巡检执行体 wrapper（v3）
#  - flock 防重入：上一轮没跑完，本轮直接跳过
#  - 拉取远端脚本并做 sha256 pin（pin 填了就强制校验，不符不执行）
#  - 失败 / 超时 / 崩溃一律写日志，不再静默
WRAPPER_VERSION="3"
LOG_FILE="/var/log/incus_clean.log"
LOCAL_DIR="/usr/local/lib/incus-guard"
LOCAL="$LOCAL_DIR/incus.sh"
LOCK="/run/incus_guard.lock"
URL="https://raw.githubusercontent.com/huoren-release/incus/main/incus.sh"
PIN_SHA256=""
# 远端更新开关：1 = 每轮拉远端并覆盖本地；0 = 只跑本地副本。
# 首次部署保持 0（仓库里的 incus.sh 还是旧版），确认仓库已更新后可改为 1。
ENABLE_REMOTE=0
MAX_SECONDS=600

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin"
mkdir -p "$LOCAL_DIR"

exec 9>"$LOCK"
flock -n 9 || { echo "[$(date '+%F %T')] 上一轮未结束，跳过本轮" >> "$LOG_FILE"; exit 0; }

TMP_OUT=$(mktemp); trap 'rm -f "$TMP_OUT"' EXIT
START=$(date +%s)
RC_NOTE=""

# 只在开启远端更新时才拉取
if [ "$ENABLE_REMOTE" = "1" ]; then
    if ! curl -sLf --max-time 120 -H "Cache-Control: no-cache" -o "$LOCAL.tmp" "$URL"; then
        echo "[$(date '+%F %T')] ⚠ 拉取 incus.sh 失败（网络或仓库不可达），改用本地副本" >> "$LOG_FILE"
        rm -f "$LOCAL.tmp"
        RC_NOTE="拉取失败"
    elif [ -n "$PIN_SHA256" ]; then
        if echo "$PIN_SHA256  $LOCAL.tmp" | sha256sum -c - >/dev/null 2>&1; then
            mv -f "$LOCAL.tmp" "$LOCAL"
        else
            echo "[$(date '+%F %T')] ⚠ 远端 sha256 与 pin 不符，拒绝执行（沿用本地副本）" >> "$LOG_FILE"
            rm -f "$LOCAL.tmp"
            RC_NOTE="pin 不符"
        fi
    else
        mv -f "$LOCAL.tmp" "$LOCAL"
    fi
fi

[ -x "$LOCAL" ] || { echo "[$(date '+%F %T')] ⚠ 无可用 incus.sh，终止" >> "$LOG_FILE"; exit 1; }

timeout "$MAX_SECONDS" bash "$LOCAL" > "$TMP_OUT" 2>&1
RC=$?
DUR=$(( $(date +%s) - START ))

sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g' "$TMP_OUT" | sed -E 's/\r/\n/g' > "$TMP_OUT.clean"

# 事件入库
if grep -qE "违规:|重装成功|重装失败|FATAL" "$TMP_OUT.clean" 2>/dev/null; then
    if [ -f "$LOG_FILE" ] && [ "$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)" -gt 102400 ]; then
        tail -n 300 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
        echo "--- $(date '+%F %T') 日志超 100KB 已裁剪" >> "$LOG_FILE"
    fi
    echo "=== [$(date '+%F %T')] 🚨 巡检事件（rc=$RC 耗时=${DUR}s） ===" >> "$LOG_FILE"
    grep -E "违规:|重装成功|重装失败|FATAL" "$TMP_OUT.clean" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
fi

# 异常兜底：非零退出、超时、或明显过慢都要留痕
if [ "$RC" -ne 0 ] || [ "$DUR" -gt 300 ]; then
    echo "[$(date '+%F %T')] ⚠ 巡检异常 rc=$RC 耗时=${DUR}s ${RC_NOTE}" >> "$LOG_FILE"
    tail -n 20 "$TMP_OUT.clean" >> "$LOG_FILE" 2>/dev/null
fi

rm -f "$TMP_OUT.clean"
exit 0
WRAP

bash -n "$WRAPPER" || { echo "FATAL: wrapper 语法错误"; exit 1; }
chmod 755 "$WRAPPER"

# ---------------------------------------------------------------- systemd
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

# ---------------------------------------------------------------- cron
OLD=$(crontab -l 2>/dev/null | grep -v "incus_cron.sh" || true)
printf "%s\n*/5 * * * * %s\n" "$OLD" "$WRAPPER" | grep -v '^$' | crontab -
log "crontab 已写入（每 5 分钟）"

# ---------------------------------------------------------------- 立即应用
log "执行首轮应用..."
bash "$WRAPPER"
log "首轮完成，最近日志："
tail -n 15 "$LOG_FILE" 2>/dev/null || true

echo "------------------------------------------------"
log "部署完成。"
log "  巡检：$WRAPPER（手动跑：$WRAPPER）"
log "  仅防火墙：$WRAPPER 里那份 incus.sh 支持 --apply-only"
log "  只扫描不重装：bash /usr/local/lib/incus-guard/incus.sh --scan-only"
log "  日志：$LOG_FILE"