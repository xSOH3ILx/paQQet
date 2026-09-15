#!/usr/bin/env bash
#===============================================================================
# paQQet v4.0 - Multi-Exit Raw-Packet Tunnel Manager (paqet / KCP)
#
# Topology:  IRAN HUB (client, N instances)  ==KCP over raw TCP==>  N EXIT NODES
#
# Rewritten & hardened:
#   * schema-correct paqet YAML (role/listen/network/server/transport)
#   * per-instance, scoped iptables rules inside dedicated PAQQET_* chains
#   * boot-persistent firewall + sysctl (no rule loss after reboot)
#   * non-destructive core upgrade (existing tunnels survive)
#   * real end-to-end watchdog (inbound packet-counter delta, not one-way ping)
#   * safe defaults: 0600 configs, SOCKS5 bound to loopback or auth-protected
#   * full non-interactive CLI for automation
#===============================================================================
set -o pipefail

SCRIPT_VERSION="4.0.0"
PAQET_REPO="hanselime/paqet"

BIN_PATH="/usr/local/bin/paqet"
SELF_PATH="/usr/local/bin/paQQet"
CONFIG_DIR="/etc/paqet"
META_DIR="/etc/paqet/meta"
STATE_DIR="/var/lib/paqqet"
BACKUP_DIR="/root"
STRICT_FILE="/etc/paqet/strict_fw"
SYSCTL_CONF="/etc/sysctl.d/99-paqqet.conf"
MODULES_CONF="/etc/modules-load.d/99-paqqet.conf"
LIMITS_CONF="/etc/security/limits.d/99-paqqet.conf"
SERVICE_TEMPLATE="/etc/systemd/system/paqet@.service"
FW_SCRIPT="/usr/local/bin/paqqet-firewall.sh"
FW_SERVICE="/etc/systemd/system/paqqet-firewall.service"
WD_SCRIPT="/usr/local/bin/paqqet-watchdog.sh"
WD_SERVICE="/etc/systemd/system/paqqet-watchdog.service"
WD_TIMER="/etc/systemd/system/paqqet-watchdog.timer"
WD_LOG="/var/log/paqqet-watchdog.log"
LB_CONF="/etc/paqet/haproxy-paqqet.cfg"
LB_SERVICE="/etc/systemd/system/paqqet-lb.service"

# ---- defaults (overridable by env or CLI flags) -------------------------------
DEF_EXIT_PORT="${PAQQET_EXIT_PORT:-9443}"      # high, non-standard port (docs: never 80/443/22)
DEF_MTU="${PAQQET_MTU:-1350}"                  # paqet valid range 50-1500, safe default 1350
DEF_CONN="${PAQQET_CONN:-4}"                   # parallel KCP links (1-256); client addr must be :0
DEF_PROFILE="${PAQQET_PROFILE:-fast3}"
DEF_WND="${PAQQET_WND:-2048}"                  # rcvwnd/sndwnd (1-32768)
DEF_BLOCK="${PAQQET_BLOCK:-aes}"
DEF_TCP_FLAG="${PAQQET_TCP_FLAG:-PA}"          # must be identical on both sides
DEF_LB_BASE="${PAQQET_LB_BASE:-20000}"         # base port for loopback tunnel entries
STRICT_FW="${PAQQET_STRICT_FW:-1}"             # 1 = also DROP tunnel packets in filter INPUT
ASSUME_YES="${PAQQET_ASSUME_YES:-0}"

if [[ -t 1 ]]; then
	RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'
	BLUE=$'\033[0;34m'; CYAN=$'\033[0;36m'; MAGENTA=$'\033[0;35m'
	BOLD=$'\033[1m'; NC=$'\033[0m'
else
	RED=""; GREEN=""; YELLOW=""; BLUE=""; CYAN=""; MAGENTA=""; BOLD=""; NC=""
fi

log_info() { echo -e "${CYAN}[INFO]${NC} $*" >&2; }
log_ok()   { echo -e "${GREEN}[ OK ]${NC} $*" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
log_err()  { echo -e "${RED}[FAIL]${NC} $*" >&2; }
die()      { log_err "$*"; exit 1; }

TTY_DEV=""
[[ -r /dev/tty && -w /dev/tty ]] && TTY_DEV="/dev/tty"

# ask <prompt> [default]  -> echoes answer (prompt goes to stderr)
ask() {
	local prompt="$1" def="${2:-}" ans=""
	if [[ "$ASSUME_YES" == "1" ]]; then printf '%s\n' "$def"; return 0; fi
	if [[ -n "$TTY_DEV" ]]; then
		read -r -p "$prompt" ans < "$TTY_DEV" || ans=""
	else
		read -r -p "$prompt" ans || ans=""
	fi
	printf '%s\n' "${ans:-$def}"
}

ask_secret() {
	local prompt="$1" ans=""
	if [[ -n "$TTY_DEV" ]]; then
		read -r -s -p "$prompt" ans < "$TTY_DEV" || ans=""
	else
		read -r -s -p "$prompt" ans || ans=""
	fi
	echo >&2
	printf '%s\n' "$ans"
}

confirm() {
	local prompt="$1" def="${2:-y}" a
	[[ "$ASSUME_YES" == "1" ]] && return 0
	a=$(ask "$prompt [${def}/$([[ $def == y ]] && echo n || echo y)]: " "$def")
	[[ "$a" =~ ^[Yy]([Ee][Ss])?$ ]]
}

pause_prompt() {
	local msg="${1:-Press [Enter] to continue...}"
	[[ "$ASSUME_YES" == "1" ]] && return 0
	echo -e "\n${YELLOW}${msg}${NC}" >&2
	if [[ -n "$TTY_DEV" ]]; then read -r -n 1 -s _x < "$TTY_DEV" || true; else read -r _x || true; fi
}

need_root() { [[ $EUID -eq 0 ]] || die "This script must run as root (sudo -i)."; }
have() { command -v "$1" >/dev/null 2>&1; }

#-------------------------------------------------------------------------------
# Validators
#-------------------------------------------------------------------------------
valid_name()  { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$ ]]; }
valid_port()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 )); }
valid_mtu()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 576 && $1 <= 1500 )); }
valid_conn()  { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 256 )); }
valid_wnd()   { [[ "$1" =~ ^[0-9]+$ ]] && (( $1 >= 128 && $1 <= 32768 )); }
valid_mac()   { [[ "${1,,}" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]; }
valid_ipv4()  {
	local ip="$1" o
	[[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
	IFS='.' read -r -a o <<< "$ip"
	for n in "${o[@]}"; do (( n >= 0 && n <= 255 )) || return 1; done
	return 0
}
valid_profile() { [[ "$1" =~ ^(normal|fast|fast2|fast3|lowlatency|bandwidth)$ ]]; }

# port_in_use <port> [tcp|udp]  -> true if a *kernel socket* already listens
port_in_use() {
	local p="$1" proto="${2:-tcp}"
	have ss || return 1
	if [[ "$proto" == "udp" ]]; then
		ss -lnuH 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${p}$"
	else
		ss -lntH 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
	fi
}

# first free local port starting at $1 (also avoids ports claimed by other instances)
free_port_from() {
	local p="${1:-20000}" used
	used="$(grep -hoE '^LOCAL_PORTS="[^"]*"' "$META_DIR"/*.meta 2>/dev/null | tr -d '"' | cut -d= -f2 | tr ',' ' ')"
	while (( p < 65000 )); do
		if ! port_in_use "$p" tcp && ! port_in_use "$p" udp && ! grep -qw "$p" <<< "$used"; then
			printf '%s\n' "$p"; return 0
		fi
		p=$((p+1))
	done
	return 1
}

#-------------------------------------------------------------------------------
# Package management (apt / dnf / yum / apk / pacman)
#-------------------------------------------------------------------------------
pkg_mgr() {
	for m in apt-get dnf yum apk pacman; do have "$m" && { printf '%s\n' "$m"; return 0; }; done
	return 1
}

pkg_install() {
	local mgr; mgr=$(pkg_mgr) || { log_warn "No supported package manager found; install dependencies manually."; return 1; }
	case "$mgr" in
		apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 ;;
		dnf)     dnf install -y -q "$@" >/dev/null 2>&1 ;;
		yum)     yum install -y -q "$@" >/dev/null 2>&1 ;;
		apk)     apk add --no-cache "$@" >/dev/null 2>&1 ;;
		pacman)  pacman -Sy --noconfirm "$@" >/dev/null 2>&1 ;;
	esac
}

# Linux paqet builds are statically linked -> libpcap-dev is NOT required.
ensure_deps() {
	log_info "Checking dependencies..."
	local mgr; mgr=$(pkg_mgr) || true
	local want=() cmd pkg
	for pair in "curl:curl" "ip:iproute2" "iptables:iptables" "tar:tar" "ss:iproute2" "tcpdump:tcpdump"; do
		cmd="${pair%%:*}"; pkg="${pair##*:}"
		have "$cmd" || want+=("$pkg")
	done
	case "$mgr" in
		apt-get) have arping || want+=("iputils-arping"); have openssl || want+=("openssl"); want+=("ca-certificates") ;;
		dnf|yum) have arping || want+=("iputils"); have openssl || want+=("openssl") ;;
		apk)     have arping || want+=("iputils"); have openssl || want+=("openssl") ;;
		pacman)  have arping || want+=("iputils"); have openssl || want+=("openssl") ;;
	esac
	if ((${#want[@]})); then
		log_info "Installing: ${want[*]}"
		pkg_install "${want[@]}" || log_warn "Some packages could not be installed automatically."
	fi
	for c in curl ip iptables tar; do
		have "$c" || die "Required command '$c' is missing and could not be installed."
	done
	log_ok "Dependencies ready."
}

#-------------------------------------------------------------------------------
# Environment sanity (raw sockets are impossible in some virtualisations)
#-------------------------------------------------------------------------------
check_environment() {
	local virt=""
	have systemd-detect-virt && virt=$(systemd-detect-virt 2>/dev/null || true)
	case "$virt" in
		openvz|lxc|lxc-libvirt|docker|podman)
			log_warn "Container virtualisation detected ($virt). paqet needs AF_PACKET raw capture/injection"
			log_warn "which is usually unavailable on OpenVZ/LXC. KVM or bare metal is required." ;;
	esac
	if [[ -n "${DETECTED_IFACE:-}" ]] && ! ip -o link show dev "$DETECTED_IFACE" 2>/dev/null | grep -q 'link/ether'; then
		log_warn "Interface $DETECTED_IFACE is not Ethernet-type (no MAC). paqet crafts Ethernet frames and"
		log_warn "will not work on point-to-point links (venet/ppp/tun). Choose an eth-type interface."
	fi
}

#-------------------------------------------------------------------------------
# Paqet core: download / upgrade (NON-destructive: existing tunnels survive)
#-------------------------------------------------------------------------------
arch_tag() {
	case "$(uname -m)" in
		x86_64|amd64)  echo amd64 ;;
		aarch64|arm64) echo arm64 ;;
		*) return 1 ;;
	esac
}

is_elf() {
	local magic
	magic=$(od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n')
	[[ "$magic" == "7f454c46" ]]
}

resolve_asset_url() {
	local ver="$1" a; a=$(arch_tag) || return 1
	if [[ -z "$ver" || "$ver" == "latest" ]]; then
		printf 'https://github.com/%s/releases/latest/download/paqet_linux_%s\n' "$PAQET_REPO" "$a"
	else
		printf 'https://github.com/%s/releases/download/%s/paqet_linux_%s\n' "$PAQET_REPO" "$ver" "$a"
	fi
}

# fallback: ask the GitHub API for any asset matching linux+arch (tar.gz / zip / raw)
resolve_asset_url_api() {
	local ver="$1" a api json url; a=$(arch_tag) || return 1
	if [[ -z "$ver" || "$ver" == "latest" ]]; then
		api="https://api.github.com/repos/${PAQET_REPO}/releases/latest"
	else
		api="https://api.github.com/repos/${PAQET_REPO}/releases/tags/${ver}"
	fi
	json=$(curl -fsSL --connect-timeout 10 --max-time 25 "$api" 2>/dev/null) || return 1
	url=$(grep -oE '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$json" \
		| cut -d'"' -f4 | grep -iE "linux[_-]?${a}" | grep -viE '\.(sha256|md5|asc|sig)$' | head -n1)
	[[ -n "$url" ]] && printf '%s\n' "$url"
}

install_core() {
	local want_ver="${1:-${PAQET_VERSION:-latest}}"
	arch_tag >/dev/null || die "Unsupported CPU architecture: $(uname -m) (only amd64/arm64)."
	mkdir -p "$CONFIG_DIR" "$META_DIR" "$STATE_DIR" /usr/local/bin
	chmod 700 "$CONFIG_DIR" "$META_DIR" 2>/dev/null || true

	# Remember which instances are running, so an upgrade does not kill the hub.
	local running=()
	mapfile -t running < <(systemctl list-units 'paqet@*.service' --state=running --no-legend 2>/dev/null | awk '{print $1}')

	local tmp url
	tmp=$(mktemp /tmp/paqet.XXXXXX) || die "mktemp failed"
	url=$(resolve_asset_url "$want_ver")
	log_info "Downloading paqet core ($want_ver, $(arch_tag))..."
	if ! curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 180 "$url" -o "$tmp"; then
		log_warn "Direct asset download failed, querying GitHub API..."
		url=$(resolve_asset_url_api "$want_ver") || { rm -f "$tmp"; die "Cannot resolve a paqet release asset (network/GitHub blocked?)."; }
		curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 180 "$url" -o "$tmp" \
			|| { rm -f "$tmp"; die "Download failed: $url"; }
	fi

	# Unpack when the asset is an archive
	if ! is_elf "$tmp"; then
		local dir; dir=$(mktemp -d /tmp/paqetx.XXXXXX)
		if tar -tzf "$tmp" >/dev/null 2>&1; then
			tar -xzf "$tmp" -C "$dir"
		elif have unzip && unzip -tq "$tmp" >/dev/null 2>&1; then
			unzip -qo "$tmp" -d "$dir"
		fi
		local found
		found=$(find "$dir" -type f -name 'paqet*' ! -name '*.yaml' ! -name '*.md' | head -n1)
		[[ -n "$found" ]] || { rm -rf "$dir" "$tmp"; die "Downloaded asset contains no paqet binary."; }
		mv -f "$found" "$tmp"
		rm -rf "$dir"
	fi
	is_elf "$tmp" || { rm -f "$tmp"; die "Downloaded file is not a Linux binary."; }

	chmod 755 "$tmp"
	local ver_out=""
	ver_out=$("$tmp" version 2>/dev/null | sed -n '1p') || ver_out=""
	[[ -z "$ver_out" ]] && ver_out=$("$tmp" --version 2>/dev/null | sed -n '1p')

	# Stop instances only for the few seconds needed to swap the binary.
	if ((${#running[@]})); then
		log_info "Temporarily stopping ${#running[@]} running tunnel(s) for the binary swap..."
		systemctl stop "${running[@]}" 2>/dev/null || true
	fi
	install -m 0755 "$tmp" "$BIN_PATH"
	rm -f "$tmp"
	log_ok "paqet installed at $BIN_PATH ${ver_out:+($ver_out)}"

	# Keep a copy of this manager as a system command
	if [[ -f "${BASH_SOURCE[0]}" && "${BASH_SOURCE[0]}" != "$SELF_PATH" ]]; then
		install -m 0755 "${BASH_SOURCE[0]}" "$SELF_PATH" 2>/dev/null || true
	fi

	install_service_template
	install_firewall_unit
	if ((${#running[@]})); then
		systemctl start "${running[@]}" 2>/dev/null || true
		log_ok "Tunnels restarted: ${running[*]}"
	fi
}

# paqet CLI shape: modern builds use "paqet run -c file"; probe once and cache.
paqet_exec_line() {
	local line="$BIN_PATH run -c $CONFIG_DIR/%i.yaml"
	if [[ -x "$BIN_PATH" ]]; then
		if ! "$BIN_PATH" run --help >/dev/null 2>&1; then
			if "$BIN_PATH" --help 2>&1 | grep -qiE '^[[:space:]]*run[[:space:]]'; then
				: # run exists
			else
				line="$BIN_PATH -c $CONFIG_DIR/%i.yaml"
			fi
		fi
	fi
	printf '%s\n' "$line"
}

gen_key() {
	local k=""
	if [[ -x "$BIN_PATH" ]]; then
		k=$("$BIN_PATH" secret 2>/dev/null | tr -d '\r' | grep -oE '[A-Za-z0-9+/=_-]{16,}' | head -n1)
	fi
	[[ -z "$k" ]] && have openssl && k=$(openssl rand -base64 32 | tr -d '\n=' )
	[[ -z "$k" ]] && k=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
	printf '%s\n' "$k"
}

#-------------------------------------------------------------------------------
# Network discovery (non-interactive safe; env overrides honoured)
#   PAQQET_IFACE / PAQQET_LOCAL_IP / PAQQET_ROUTER_MAC
#-------------------------------------------------------------------------------
detect_network_details() {
	local target="${1:-1.1.1.1}" route gw
	DETECTED_IFACE="${PAQQET_IFACE:-}"
	DETECTED_IP="${PAQQET_LOCAL_IP:-}"
	DETECTED_MAC="${PAQQET_ROUTER_MAC:-}"

	route=$(ip route get "$target" 2>/dev/null | head -n1)
	[[ -z "$route" ]] && route=$(ip route show default 2>/dev/null | head -n1)

	[[ -z "$DETECTED_IFACE" ]] && DETECTED_IFACE=$(sed -n 's/.* dev \([^ ]*\).*/\1/p' <<< "$route" | head -n1)
	[[ -z "$DETECTED_IFACE" ]] && DETECTED_IFACE=$(ip -4 route show default | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)
	[[ -n "$DETECTED_IFACE" ]] || die "Cannot determine the outbound network interface."

	[[ -z "$DETECTED_IP" ]] && DETECTED_IP=$(sed -n 's/.* src \([^ ]*\).*/\1/p' <<< "$route" | head -n1)
	[[ -z "$DETECTED_IP" ]] && DETECTED_IP=$(ip -4 -o addr show dev "$DETECTED_IFACE" scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
	valid_ipv4 "${DETECTED_IP:-}" || die "Cannot determine the local IPv4 address of $DETECTED_IFACE."

	gw=$(sed -n 's/.* via \([^ ]*\).*/\1/p' <<< "$route" | head -n1)
	[[ -z "$gw" ]] && gw=$(ip -4 route show default | sed -n 's/.* via \([^ ]*\).*/\1/p' | head -n1)

	if [[ -z "$DETECTED_MAC" && -n "$gw" ]]; then
		DETECTED_MAC=$(ip -4 neigh show to "$gw" dev "$DETECTED_IFACE" 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
		if [[ -z "$DETECTED_MAC" ]]; then
			ping -c 2 -W 1 "$gw" >/dev/null 2>&1 || true
			have arping && arping -c 2 -w 2 -I "$DETECTED_IFACE" "$gw" >/dev/null 2>&1 || true
			DETECTED_MAC=$(ip -4 neigh show to "$gw" dev "$DETECTED_IFACE" 2>/dev/null | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -n1)
		fi
	fi
	# Some providers use an on-link /32 gateway: fall back to the default-route neighbour.
	if [[ -z "$DETECTED_MAC" ]]; then
		DETECTED_MAC=$(ip -4 neigh show dev "$DETECTED_IFACE" 2>/dev/null | awk '/REACHABLE|STALE|DELAY/ {print $5; exit}')
	fi
	if [[ -z "$DETECTED_MAC" ]]; then
		if [[ -n "$TTY_DEV" && "$ASSUME_YES" != "1" ]]; then
			DETECTED_MAC=$(ask "Gateway MAC could not be detected. Enter router MAC (aa:bb:cc:dd:ee:ff): " "")
		fi
	fi
	valid_mac "${DETECTED_MAC:-}" || die "Invalid/missing gateway MAC. Set it with PAQQET_ROUTER_MAC=aa:bb:cc:dd:ee:ff"
	DETECTED_MAC="${DETECTED_MAC,,}"

	PUBLIC_IP=$(curl -fsS --max-time 6 https://api.ipify.org 2>/dev/null || curl -fsS --max-time 6 https://ifconfig.me 2>/dev/null || true)
	valid_ipv4 "${PUBLIC_IP:-}" || PUBLIC_IP="$DETECTED_IP"

	check_environment
	log_ok "iface=$DETECTED_IFACE  local_ip=$DETECTED_IP  gw_mac=$DETECTED_MAC  public_ip=$PUBLIC_IP"
	if [[ "$PUBLIC_IP" != "$DETECTED_IP" ]]; then
		log_warn "This host is behind 1:1 NAT. Config keeps the private IP ($DETECTED_IP);"
		log_warn "remote peers must connect to the public IP ($PUBLIC_IP)."
	fi
}

#-------------------------------------------------------------------------------
# Kernel / NIC tuning
#-------------------------------------------------------------------------------
reserved_ports_list() {
	local out="" p
	shopt -s nullglob
	for m in "$META_DIR"/*.meta; do
		# shellcheck disable=SC1090
		( . "$m"; [[ -n "${PORT:-}" ]] && echo "$PORT"; [[ -n "${LOCAL_PORTS:-}" ]] && tr ',' '\n' <<< "$LOCAL_PORTS" )
	done | sort -un | while read -r p; do [[ -n "$p" ]] && printf '%s,' "$p"; done | sed 's/,$//'
}

apply_linux_optimizations() {
	log_info "Applying kernel / network tuning..."

	# conntrack keys only exist when the module is loaded
	modprobe nf_conntrack >/dev/null 2>&1 || true
	echo "nf_conntrack" > "$MODULES_CONF" 2>/dev/null || true

	local cc_avail="" qdisc_line="" cc_line=""
	cc_avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
	if ! grep -qw bbr <<< "$cc_avail"; then modprobe tcp_bbr >/dev/null 2>&1 || true; cc_avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true); fi
	if grep -qw bbr <<< "$cc_avail"; then
		cc_line="net.ipv4.tcp_congestion_control = bbr"
		if [[ -d /sys/module/sch_fq ]] || modprobe sch_fq >/dev/null 2>&1; then qdisc_line="net.core.default_qdisc = fq"; else qdisc_line="net.core.default_qdisc = fq_codel"; fi
	else
		log_warn "BBR not available in this kernel; keeping current congestion control."
		qdisc_line="net.core.default_qdisc = fq_codel"
	fi

	{
		echo "# paQQet ${SCRIPT_VERSION} - tuning for raw-packet/KCP tunnels"
		echo "fs.file-max = 2097152"
		echo "net.core.rmem_max = 67108864"
		echo "net.core.wmem_max = 67108864"
		echo "net.core.rmem_default = 8388608"
		echo "net.core.wmem_default = 8388608"
		echo "net.core.optmem_max = 25165824"
		echo "net.core.netdev_max_backlog = 100000"
		echo "net.core.somaxconn = 65535"
		echo "$qdisc_line"
		[[ -n "$cc_line" ]] && echo "$cc_line"
		echo "net.ipv4.tcp_rmem = 4096 87380 33554432"
		echo "net.ipv4.tcp_wmem = 4096 65536 33554432"
		echo "net.ipv4.tcp_fastopen = 3"
		echo "net.ipv4.tcp_slow_start_after_idle = 0"
		echo "net.ipv4.tcp_tw_reuse = 1"
		echo "net.ipv4.tcp_fin_timeout = 20"
		echo "net.ipv4.tcp_max_syn_backlog = 32768"
		echo "net.ipv4.tcp_mtu_probing = 1"
		echo "net.ipv4.tcp_sack = 1"
		echo "net.ipv4.tcp_window_scaling = 1"
		echo "net.ipv4.tcp_keepalive_time = 300"
		echo "net.ipv4.tcp_keepalive_intvl = 30"
		echo "net.ipv4.tcp_keepalive_probes = 5"
		# Keep the ephemeral range away from service ports used by tunnels/panels
		echo "net.ipv4.ip_local_port_range = 16384 60999"
		local rp; rp=$(reserved_ports_list)
		[[ -n "$rp" ]] && echo "net.ipv4.ip_local_reserved_ports = $rp"
		if [[ -d /proc/sys/net/netfilter ]]; then
			echo "net.netfilter.nf_conntrack_max = 1048576"
			echo "net.netfilter.nf_conntrack_tcp_timeout_established = 86400"
		fi
	} > "$SYSCTL_CONF"

	sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || log_warn "Some sysctl keys were rejected by this kernel (safe to ignore)."

	cat > "$LIMITS_CONF" << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

	if [[ -n "${DETECTED_IFACE:-}" ]] && ip link show "$DETECTED_IFACE" >/dev/null 2>&1; then
		ip link set dev "$DETECTED_IFACE" txqueuelen 10000 2>/dev/null || true
		have ethtool && ethtool -G "$DETECTED_IFACE" rx 4096 tx 4096 >/dev/null 2>&1 || true
	fi
	log_ok "Kernel tuning applied ($SYSCTL_CONF)."
	[[ -n "$cc_line" ]] && log_info "Note: BBR/TCP tuning helps local + exit-side TCP only. The tunnel itself is KCP."
}

#-------------------------------------------------------------------------------
# Firewall: dedicated PAQQET_* chains, rebuilt from metadata, persistent at boot
#-------------------------------------------------------------------------------
write_firewall_script() {
	cat > "$FW_SCRIPT" << 'FWEOF'
#!/usr/bin/env bash
# Generated by paQQet - rebuilds the PAQQET_* iptables chains from /etc/paqet/meta/*.meta
# Only paQQet-owned chains are touched; other rules on this box are never flushed.
set -o pipefail
META_DIR="/etc/paqet/meta"
STRICT_FILE="/etc/paqet/strict_fw"
IPT="$(command -v iptables || echo /sbin/iptables)"

strict=1
[[ -f "$STRICT_FILE" ]] && strict="$(head -n1 "$STRICT_FILE" 2>/dev/null || echo 1)"

chain_reset() { # <table> <chain> <parent-chain>
	local t="$1" c="$2" p="$3"
	"$IPT" -t "$t" -N "$c" 2>/dev/null || "$IPT" -t "$t" -F "$c" 2>/dev/null
	"$IPT" -t "$t" -C "$p" -j "$c" 2>/dev/null || "$IPT" -t "$t" -I "$p" 1 -j "$c"
}

chain_reset raw    PAQQET_RAW_PRE PREROUTING
chain_reset raw    PAQQET_RAW_OUT OUTPUT
chain_reset mangle PAQQET_MG_OUT  OUTPUT
chain_reset filter PAQQET_IN      INPUT

shopt -s nullglob
for m in "$META_DIR"/*.meta; do
	ROLE=""; PORT=""; REMOTE_IP=""; REMOTE_PORT=""
	# shellcheck disable=SC1090
	. "$m" 2>/dev/null || continue
	case "$ROLE" in
	server)
		[[ -n "$PORT" ]] || continue
		# kernel must not track or answer packets that belong to the raw tunnel
		"$IPT" -t raw    -A PAQQET_RAW_PRE -p tcp --dport "$PORT" -j NOTRACK
		"$IPT" -t raw    -A PAQQET_RAW_OUT -p tcp --sport "$PORT" -j NOTRACK
		"$IPT" -t mangle -A PAQQET_MG_OUT  -p tcp --sport "$PORT" --tcp-flags RST RST -j DROP
		[[ "$strict" == "1" ]] && "$IPT" -A PAQQET_IN -p tcp --dport "$PORT" -j DROP
		;;
	client)
		[[ -n "$REMOTE_IP" && -n "$REMOTE_PORT" ]] || continue
		"$IPT" -t raw    -A PAQQET_RAW_OUT -p tcp -d "$REMOTE_IP" --dport "$REMOTE_PORT" -j NOTRACK
		"$IPT" -t raw    -A PAQQET_RAW_PRE -p tcp -s "$REMOTE_IP" --sport "$REMOTE_PORT" -j NOTRACK
		"$IPT" -t mangle -A PAQQET_MG_OUT  -p tcp -d "$REMOTE_IP" --dport "$REMOTE_PORT" --tcp-flags RST RST -j DROP
		[[ "$strict" == "1" ]] && "$IPT" -A PAQQET_IN -p tcp -s "$REMOTE_IP" --sport "$REMOTE_PORT" -j DROP
		;;
	esac
done
exit 0
FWEOF
	chmod 0755 "$FW_SCRIPT"
}

install_firewall_unit() {
	write_firewall_script
	echo "$STRICT_FW" > "$STRICT_FILE"
	cat > "$FW_SERVICE" << EOF
[Unit]
Description=paQQet firewall rules (raw/mangle/filter chains for paqet tunnels)
After=network-pre.target
Wants=network-pre.target
Before=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$FW_SCRIPT

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable paqqet-firewall.service >/dev/null 2>&1 || true
}

apply_firewall() {
	install_firewall_unit
	"$FW_SCRIPT" || log_warn "Some firewall rules could not be applied."
	log_ok "Firewall chains rebuilt (PAQQET_RAW_PRE / PAQQET_RAW_OUT / PAQQET_MG_OUT / PAQQET_IN)."
}

remove_firewall_all() {
	systemctl disable --now paqqet-firewall.service >/dev/null 2>&1 || true
	local ipt; ipt=$(command -v iptables || echo /sbin/iptables)
	"$ipt" -t raw    -D PREROUTING -j PAQQET_RAW_PRE 2>/dev/null || true
	"$ipt" -t raw    -D OUTPUT     -j PAQQET_RAW_OUT 2>/dev/null || true
	"$ipt" -t mangle -D OUTPUT     -j PAQQET_MG_OUT  2>/dev/null || true
	"$ipt"           -D INPUT      -j PAQQET_IN      2>/dev/null || true
	for c in PAQQET_RAW_PRE PAQQET_RAW_OUT; do "$ipt" -t raw -F "$c" 2>/dev/null; "$ipt" -t raw -X "$c" 2>/dev/null; done
	"$ipt" -t mangle -F PAQQET_MG_OUT 2>/dev/null; "$ipt" -t mangle -X PAQQET_MG_OUT 2>/dev/null
	"$ipt" -F PAQQET_IN 2>/dev/null; "$ipt" -X PAQQET_IN 2>/dev/null
	rm -f "$FW_SCRIPT" "$FW_SERVICE" "$STRICT_FILE"
	systemctl daemon-reload
}

#-------------------------------------------------------------------------------
# systemd template
#-------------------------------------------------------------------------------
install_service_template() {
	local exec_line; exec_line=$(paqet_exec_line)
	cat > "$SERVICE_TEMPLATE" << EOF
[Unit]
Description=paQQet raw-packet tunnel instance (%i)
Documentation=https://github.com/${PAQET_REPO}
After=network-online.target paqqet-firewall.service
Wants=network-online.target paqqet-firewall.service
StartLimitIntervalSec=0
StartLimitBurst=0

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
ExecStart=${exec_line}
Restart=always
RestartSec=3
TimeoutStopSec=15
KillMode=mixed
LimitNOFILE=1048576
LimitNPROC=512000
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_NET_BIND_SERVICE
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
}

#-------------------------------------------------------------------------------
# YAML builders
#-------------------------------------------------------------------------------
# kcp_block <key> <mtu> <profile> <wnd>   (indented with 4 spaces, under transport.kcp)
kcp_block() {
	local key="$1" mtu="$2" prof="$3" wnd="$4"
	echo "  kcp:"
	case "$prof" in
		bandwidth)
			echo "    mode: \"manual\""
			echo "    nodelay: 0"
			echo "    interval: 20"
			echo "    resend: 2"
			echo "    nocongestion: 0"
			echo "    wdelay: true"
			echo "    acknodelay: false" ;;
		lowlatency)
			echo "    mode: \"manual\""
			echo "    nodelay: 1"
			echo "    interval: 10"
			echo "    resend: 2"
			echo "    nocongestion: 1"
			echo "    wdelay: false"
			echo "    acknodelay: true" ;;
		normal|fast|fast2|fast3)
			echo "    mode: \"${prof}\"" ;;
		*)
			echo "    mode: \"fast3\"" ;;
	esac
	echo "    mtu: ${mtu}"
	echo "    rcvwnd: ${wnd}"
	echo "    sndwnd: ${wnd}"
	echo "    block: \"${DEF_BLOCK}\""
	echo "    key: \"${key}\""
	echo "    smuxbuf: 8388608"
	echo "    streambuf: 4194304"
	# Defaults (2s/8s) tear the session down on brief Iranian packet-loss bursts.
	echo "    smuxkalive: 5"
	echo "    smuxktimeout: 30"
}

validate_yaml() {
	local f="$1"
	if have python3 && python3 -c 'import yaml' >/dev/null 2>&1; then
		python3 - "$f" << 'PYEOF' || { log_err "YAML syntax error in $1"; return 1; }
import sys, yaml
yaml.safe_load(open(sys.argv[1]))
PYEOF
	fi
	grep -q $'\t' "$f" && { log_err "Tab character found in $f (YAML forbids tabs)."; return 1; }
	return 0
}

write_meta() { # write_meta <instance> <key=value>...
	local inst="$1"; shift
	mkdir -p "$META_DIR"; chmod 700 "$META_DIR"
	{ echo "# paQQet instance metadata"; for kv in "$@"; do echo "$kv"; done; } > "$META_DIR/${inst}.meta"
	chmod 600 "$META_DIR/${inst}.meta"
}

start_instance() { # start_instance <instance>
	local inst="$1"
	[[ -n "$inst" ]] || { log_err "start_instance called without an instance name"; return 1; }
	local svc="paqet@${inst}"
	systemctl enable "$svc" >/dev/null 2>&1 || true
	systemctl restart "$svc" || true
	sleep 3
	if systemctl is-active --quiet "$svc"; then
		log_ok "Instance ${BOLD}${inst}${NC} is ACTIVE."
		return 0
	fi
	log_err "Instance ${inst} failed to start. Last log lines:"
	journalctl -u "$svc" -n 25 --no-pager 2>/dev/null | sed 's/^/    /' >&2
	return 1
}

#-------------------------------------------------------------------------------
# EXIT NODE (Kharej / server role)
#-------------------------------------------------------------------------------
configure_server() {
	local name="$1" port="$2" key="$3" mtu="$4" prof="$5" conn="$6" wnd="$7"
	name="${name:-server}"; port="${port:-$DEF_EXIT_PORT}"; mtu="${mtu:-$DEF_MTU}"
	prof="${prof:-$DEF_PROFILE}"; conn="${conn:-$DEF_CONN}"; wnd="${wnd:-$DEF_WND}"

	valid_name "$name"   || die "Invalid instance name: $name (use A-Z a-z 0-9 _ -)"
	valid_port "$port"   || die "Invalid port: $port"
	valid_mtu "$mtu"     || die "Invalid MTU: $mtu (576-1500)"
	valid_conn "$conn"   || die "Invalid conn: $conn (1-256)"
	valid_wnd "$wnd"     || die "Invalid window: $wnd"
	valid_profile "$prof" || die "Invalid profile: $prof"
	case "$port" in 22|53|80|443|8080|8443) log_warn "Port $port is a standard/common port. paqet docs recommend a high uncommon port (e.g. 9443, 23456).";; esac
	if port_in_use "$port" tcp; then
		log_err "TCP port $port already has a kernel listener (ss -lntp). A raw-packet tunnel MUST NOT share its port"
		log_err "with a real socket: the kernel would answer/RST the tunnel packets. Choose another port."
		return 1
	fi

	[[ -z "$key" ]] && key=$(gen_key)
	[[ ${#key} -ge 16 ]] || log_warn "Secret key is shorter than 16 chars; prefer 'paqet secret' output."

	[[ -x "$BIN_PATH" ]] || die "paqet core is not installed. Run option 1 (Install/Update core) first."
	detect_network_details "1.1.1.1"
	apply_linux_optimizations

	mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
	local cfg="$CONFIG_DIR/${name}.yaml"
	{
		echo "# paQQet exit node (server) - generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "role: \"server\""
		echo ""
		echo "log:"
		echo "  level: \"info\""
		echo ""
		echo "listen:"
		echo "  addr: \":${port}\""
		echo ""
		echo "network:"
		echo "  interface: \"${DETECTED_IFACE}\""
		echo "  ipv4:"
		echo "    addr: \"${DETECTED_IP}:${port}\""   # port MUST match listen.addr
		echo "    router_mac: \"${DETECTED_MAC}\""
		echo "  tcp:"
		echo "    local_flag: [\"${DEF_TCP_FLAG}\"]"
		echo "  pcap:"
		echo "    sockbuf: 8388608"
		echo ""
		echo "transport:"
		echo "  protocol: \"kcp\""
		echo "  conn: ${conn}"
		kcp_block "$key" "$mtu" "$prof" "$wnd"
	} > "$cfg"
	chmod 600 "$cfg"
	validate_yaml "$cfg" || return 1

	write_meta "$name" "ROLE=server" "PORT=$port" "MTU=$mtu" "PROFILE=$prof" "CONN=$conn" "WND=$wnd" \
		"IFACE=$DETECTED_IFACE" "LOCAL_IP=$DETECTED_IP" "PUBLIC_IP=$PUBLIC_IP" "KEY=$key"

	install_service_template
	apply_firewall
	start_instance "$name" || return 1

	echo "" >&2
	echo -e "${GREEN}${BOLD}==============================================================${NC}" >&2
	echo -e "${GREEN}${BOLD}  PARAMETERS FOR THE IRAN HUB (client side)                    ${NC}" >&2
	echo -e "${GREEN}${BOLD}==============================================================${NC}" >&2
	echo -e "  Remote IP   : ${CYAN}${PUBLIC_IP}${NC}" >&2
	echo -e "  Remote Port : ${CYAN}${port}${NC}" >&2
	echo -e "  Secret Key  : ${YELLOW}${key}${NC}" >&2
	echo -e "  MTU/Profile : ${CYAN}${mtu} / ${prof}${NC}  (must match on both sides)" >&2
	echo -e "${GREEN}==============================================================${NC}" >&2
	log_warn "Open TCP/${port} inbound in your cloud provider firewall (SecurityGroup/NSG) too."
	log_warn "Make sure your panel (3X-UI/Xray) listens on the target port you will forward to."
}

#-------------------------------------------------------------------------------
# IRAN HUB (client role) - one instance per exit node
#-------------------------------------------------------------------------------
# Mapping syntax (comma separated):
#   2053                 -> listen <bind>:2053  target 127.0.0.1:2053
#   8080>443             -> listen <bind>:8080  target 127.0.0.1:443
#   8080>10.0.0.5:443    -> listen <bind>:8080  target 10.0.0.5:443
# Emits "listenPort|targetHost|targetPort" lines.
parse_mappings() {
	local spec="$1" item lp rest th tp
	IFS=',' read -r -a _items <<< "$spec"
	for item in "${_items[@]}"; do
		item="$(tr -d '[:space:]' <<< "$item")"
		[[ -z "$item" ]] && continue
		if [[ "$item" == *">"* ]]; then
			lp="${item%%>*}"; rest="${item#*>}"
			if [[ "$rest" == *:* ]]; then th="${rest%%:*}"; tp="${rest##*:}"; else th="127.0.0.1"; tp="$rest"; fi
		else
			lp="$item"; th="127.0.0.1"; tp="$item"
		fi
		valid_port "$lp" || { log_err "Invalid local port in mapping '$item'"; return 1; }
		valid_port "$tp" || { log_err "Invalid target port in mapping '$item'"; return 1; }
		[[ -n "$th" ]]   || { log_err "Invalid target host in mapping '$item'"; return 1; }
		printf '%s|%s|%s\n' "$lp" "$th" "$tp"
	done
}

# Globals consumed by configure_client()
reset_client_vars() {
	C_NAME=""; C_REMOTE=""; C_PORT="$DEF_EXIT_PORT"; C_KEY=""; C_PORTS=""
	C_BIND="0.0.0.0"; C_SOCKS=""; C_SOCKS_USER=""; C_SOCKS_PASS=""
	C_MTU="$DEF_MTU"; C_PROF="$DEF_PROFILE"; C_CONN="$DEF_CONN"; C_WND="$DEF_WND"; C_PROTO="tcp"
}

configure_client() {
	local name="${C_NAME}" remote="${C_REMOTE}" rport="${C_PORT}" key="${C_KEY}"
	local bind="${C_BIND:-0.0.0.0}" mtu="${C_MTU:-$DEF_MTU}" prof="${C_PROF:-$DEF_PROFILE}"
	local conn="${C_CONN:-$DEF_CONN}" wnd="${C_WND:-$DEF_WND}" proto="${C_PROTO:-tcp}"

	valid_name "$name"     || die "Invalid instance name: '$name'"
	valid_ipv4 "$remote"   || die "Remote (exit) address must be a literal IPv4: '$remote'"
	valid_port "$rport"    || die "Invalid remote port: $rport"
	[[ -n "$key" ]]        || die "Secret key is required (copy it from the exit node)."
	valid_mtu "$mtu"       || die "Invalid MTU: $mtu"
	valid_conn "$conn"     || die "Invalid conn: $conn (1-256)"
	valid_wnd "$wnd"       || die "Invalid window: $wnd"
	valid_profile "$prof"  || die "Invalid profile: $prof"
	valid_ipv4 "$bind"     || die "Invalid bind address: $bind"
	[[ -n "$C_PORTS" || -n "$C_SOCKS" ]] || die "Nothing to expose: provide port mappings and/or a SOCKS5 port."
	[[ -x "$BIN_PATH" ]]   || die "paqet core is not installed. Run option 1 first."

	if [[ -f "$META_DIR/${name}.meta" ]]; then
		confirm "Instance '$name' already exists. Overwrite?" "n" || return 1
	fi

	# --- resolve mappings & check every local port is really free -------------
	local maps=() local_ports=() m lp th tp
	if [[ -n "$C_PORTS" ]]; then
		mapfile -t maps < <(parse_mappings "$C_PORTS") || return 1
		((${#maps[@]})) || die "No valid port mapping parsed from '$C_PORTS'"
	fi
	local others_ports=""
	for f in "$META_DIR"/*.meta; do
		[[ -e "$f" ]] || continue
		[[ "$f" == "$META_DIR/${name}.meta" ]] && continue
		others_ports+=" $(grep -oE '^LOCAL_PORTS="[^"]*"' "$f" 2>/dev/null | tr -d '"' | cut -d= -f2 | tr ',' ' ')"
	done
	for m in "${maps[@]}"; do
		lp="${m%%|*}"
		if grep -qw "$lp" <<< "$others_ports"; then
			die "Local port $lp is already used by another paQQet instance. Each exit needs its own local port."
		fi
		if port_in_use "$lp" tcp || port_in_use "$lp" udp; then
			log_warn "Port $lp is currently bound by another process on this host."
			confirm "Continue anyway?" "n" || return 1
		fi
		local_ports+=("$lp")
	done
	if [[ -n "$C_SOCKS" ]]; then
		valid_port "$C_SOCKS" || die "Invalid SOCKS5 port: $C_SOCKS"
		grep -qw "$C_SOCKS" <<< "$others_ports" && die "SOCKS5 port $C_SOCKS already used by another instance."
		local_ports+=("$C_SOCKS")
	fi

	# --- SOCKS5 exposure safety ----------------------------------------------
	local socks_bind="$bind"
	if [[ -n "$C_SOCKS" && "$socks_bind" != "127.0.0.1" && ( -z "$C_SOCKS_USER" || -z "$C_SOCKS_PASS" ) ]]; then
		log_warn "A SOCKS5 proxy on ${socks_bind}:${C_SOCKS} without credentials is an OPEN PROXY."
		log_warn "Binding it to 127.0.0.1 instead (set a username/password to expose it publicly)."
		socks_bind="127.0.0.1"
	fi

	detect_network_details "$remote"
	apply_linux_optimizations

	mkdir -p "$CONFIG_DIR"; chmod 700 "$CONFIG_DIR"
	local cfg="$CONFIG_DIR/${name}.yaml"
	{
		echo "# paQQet Iran hub -> exit ${remote}:${rport} - generated $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		echo "role: \"client\""
		echo ""
		echo "log:"
		echo "  level: \"info\""
		echo ""
		if [[ -n "$C_SOCKS" ]]; then
			echo "socks5:"
			echo "  - listen: \"${socks_bind}:${C_SOCKS}\""
			echo "    username: \"${C_SOCKS_USER}\""
			echo "    password: \"${C_SOCKS_PASS}\""
			echo ""
		fi
		if ((${#maps[@]})); then
			echo "forward:"
			for m in "${maps[@]}"; do
				lp="${m%%|*}"; th="$(cut -d'|' -f2 <<< "$m")"; tp="${m##*|}"
				if [[ "$proto" == "udp" || "$proto" == "both" ]]; then
					echo "  - listen: \"${bind}:${lp}\""
					echo "    target: \"${th}:${tp}\""
					echo "    protocol: \"udp\""
				fi
				if [[ "$proto" == "tcp" || "$proto" == "both" ]]; then
					echo "  - listen: \"${bind}:${lp}\""
					echo "    target: \"${th}:${tp}\""
					echo "    protocol: \"tcp\""
				fi
			done
			echo ""
		fi
		echo "server:"
		echo "  addr: \"${remote}:${rport}\""
		echo ""
		echo "network:"
		echo "  interface: \"${DETECTED_IFACE}\""
		echo "  ipv4:"
		# Port 0 = random source port. Required for conn > 1.
		echo "    addr: \"${DETECTED_IP}:0\""
		echo "    router_mac: \"${DETECTED_MAC}\""
		echo "  tcp:"
		echo "    local_flag: [\"${DEF_TCP_FLAG}\"]"
		echo "    remote_flag: [\"${DEF_TCP_FLAG}\"]"
		echo "  pcap:"
		echo "    sockbuf: 4194304"
		echo ""
		echo "transport:"
		echo "  protocol: \"kcp\""
		echo "  conn: ${conn}"
		kcp_block "$key" "$mtu" "$prof" "$wnd"
	} > "$cfg"
	chmod 600 "$cfg"
	validate_yaml "$cfg" || return 1

	local lp_csv; lp_csv=$(IFS=,; echo "${local_ports[*]}")
	write_meta "$name" "ROLE=client" "REMOTE_IP=$remote" "REMOTE_PORT=$rport" "LOCAL_PORTS=\"${lp_csv}\"" \
		"SOCKS_PORT=${C_SOCKS}" "SOCKS_BIND=${socks_bind}" "BIND=$bind" "MTU=$mtu" "PROFILE=$prof" \
		"CONN=$conn" "WND=$wnd" "PROTO=$proto" "IFACE=$DETECTED_IFACE" "LOCAL_IP=$DETECTED_IP" "KEY=$key"

	install_service_template
	apply_firewall
	start_instance "$name" || return 1

	echo "" >&2
	echo -e "${GREEN}${BOLD}  Tunnel '${name}'  ${DETECTED_IP} (IR)  ==>  ${remote}:${rport} (exit)${NC}" >&2
	for m in "${maps[@]}"; do
		lp="${m%%|*}"; th="$(cut -d'|' -f2 <<< "$m")"; tp="${m##*|}"
		echo -e "    ${CYAN}${bind}:${lp}${NC}  ->  exit:${th}:${tp}   [${proto}]" >&2
	done
	[[ -n "$C_SOCKS" ]] && echo -e "    ${CYAN}socks5 ${socks_bind}:${C_SOCKS}${NC}" >&2
	return 0
}

# Interactive single-client wizard
client_wizard() {
	reset_client_vars
	echo -e "\n${BOLD}${BLUE}--- Add an exit node to the Iran hub ---${NC}" >&2
	C_NAME=$(ask "Instance name (e.g. de1, nl1): " "")
	valid_name "$C_NAME" || { log_err "Invalid name."; return 1; }
	C_REMOTE=$(ask "Exit server public IPv4: " "")
	valid_ipv4 "$C_REMOTE" || { log_err "Invalid IPv4."; return 1; }
	C_PORT=$(ask "Exit tunnel port [${DEF_EXIT_PORT}]: " "$DEF_EXIT_PORT")
	C_KEY=$(ask "Secret key (from the exit node): " "")
	[[ -n "$C_KEY" ]] || { log_err "Key is required."; return 1; }

	echo -e "\n  Port mappings. Examples:  ${CYAN}2053,8443${NC}   ${CYAN}8080>443${NC}   ${CYAN}9000>10.0.0.5:9000${NC}" >&2
	C_PORTS=$(ask "Ports to tunnel (empty = SOCKS5 only): " "")
	local p; p=$(ask "Protocol tcp / udp / both [tcp]: " "tcp")
	case "$p" in tcp|udp|both) C_PROTO="$p" ;; *) C_PROTO="tcp" ;; esac
	C_BIND=$(ask "Bind address for local listeners [0.0.0.0]: " "0.0.0.0")
	if confirm "Also expose a SOCKS5 proxy?" "n"; then
		C_SOCKS=$(ask "SOCKS5 port [1080]: " "1080")
		C_SOCKS_USER=$(ask "SOCKS5 username (empty = no auth, loopback only): " "")
		[[ -n "$C_SOCKS_USER" ]] && C_SOCKS_PASS=$(ask_secret "SOCKS5 password: ")
	fi
	echo -e "\n  Profiles: ${CYAN}fast3${NC} (lossy IR links, default) | fast2 | fast | normal | lowlatency | bandwidth" >&2
	C_PROF=$(ask "KCP profile [${DEF_PROFILE}]: " "$DEF_PROFILE")
	C_MTU=$(ask "MTU [${DEF_MTU}]: " "$DEF_MTU")
	C_CONN=$(ask "Parallel KCP connections [${DEF_CONN}]: " "$DEF_CONN")
	C_WND=$(ask "KCP window (rcvwnd/sndwnd) [${DEF_WND}]: " "$DEF_WND")
	configure_client
}

# Batch wizard: register several exit nodes in one pass
multi_exit_wizard() {
	local count i base
	count=$(ask "How many exit servers do you want to add now? [2]: " "2")
	[[ "$count" =~ ^[0-9]+$ ]] || { log_err "Invalid number."; return 1; }
	base=$(ask "Auto local-port base (used when you leave ports empty) [${DEF_LB_BASE}]: " "$DEF_LB_BASE")
	local shared_ports shared_proto
	echo -e "\n${CYAN}Tip:${NC} to publish the SAME service port for all exits, leave the mapping empty here" >&2
	echo -e "     and use menu option 12 (load balancer) to put HAProxy in front of the tunnels." >&2
	shared_ports=$(ask "Service port on the EXIT side to tunnel (e.g. 2053), empty to ask per node: " "")
	shared_proto=$(ask "Protocol for all nodes tcp/udp/both [tcp]: " "tcp")
	for ((i=1; i<=count; i++)); do
		echo -e "\n${BOLD}${MAGENTA}===== Exit node ${i}/${count} =====${NC}" >&2
		reset_client_vars
		C_NAME=$(ask "Name [exit${i}]: " "exit${i}")
		C_REMOTE=$(ask "Public IPv4: " "")
		valid_ipv4 "$C_REMOTE" || { log_err "Invalid IPv4, skipping."; continue; }
		C_PORT=$(ask "Tunnel port [${DEF_EXIT_PORT}]: " "$DEF_EXIT_PORT")
		C_KEY=$(ask "Secret key: " "")
		[[ -n "$C_KEY" ]] || { log_err "Key required, skipping."; continue; }
		case "$shared_proto" in tcp|udp|both) C_PROTO="$shared_proto" ;; *) C_PROTO="tcp" ;; esac
		if [[ -n "$shared_ports" ]]; then
			local auto; auto=$(free_port_from "$base") || { log_err "No free local port available."; continue; }
			C_PORTS="${auto}>127.0.0.1:${shared_ports}"
			C_BIND="127.0.0.1"
			base=$((auto+1))
			log_info "Node ${C_NAME}: local 127.0.0.1:${auto} -> exit 127.0.0.1:${shared_ports}"
		else
			C_PORTS=$(ask "Ports to tunnel (e.g. 2053 or 8080>443): " "")
			C_BIND=$(ask "Bind [0.0.0.0]: " "0.0.0.0")
		fi
		configure_client || log_err "Node ${C_NAME} failed."
	done
	echo "" >&2
	list_instances
}

#-------------------------------------------------------------------------------
# Inventory / status / removal
#-------------------------------------------------------------------------------
instance_names() {
	shopt -s nullglob
	local f n
	for f in "$META_DIR"/*.meta; do n=$(basename "$f" .meta); printf '%s\n' "$n"; done
}

meta_get() { # meta_get <instance> <KEY>
	local inst="$1" k="$2"
	[[ -f "$META_DIR/${inst}.meta" ]] || return 1
	grep -E "^${k}=" "$META_DIR/${inst}.meta" | head -n1 | cut -d= -f2- | sed 's/^"//; s/"$//'
}

list_instances() {
	local names; mapfile -t names < <(instance_names)
	if ((${#names[@]} == 0)); then log_warn "No paQQet instances configured yet."; return 0; fi
	echo -e "\n${BOLD}${BLUE}=========================== INSTANCES ===========================${NC}" >&2
	printf "  %-12s %-7s %-22s %-16s %s\n" "NAME" "ROLE" "PEER" "LOCAL PORTS" "STATE" >&2
	local n role peer lports state restarts
	for n in "${names[@]}"; do
		role=$(meta_get "$n" ROLE); lports=$(meta_get "$n" LOCAL_PORTS)
		if [[ "$role" == "server" ]]; then peer=":$(meta_get "$n" PORT) (listen)"; lports="-"
		else peer="$(meta_get "$n" REMOTE_IP):$(meta_get "$n" REMOTE_PORT)"; fi
		if systemctl is-active --quiet "paqet@${n}"; then state="${GREEN}active${NC}"; else state="${RED}$(systemctl is-active "paqet@${n}" 2>/dev/null)${NC}"; fi
		restarts=$(systemctl show -p NRestarts --value "paqet@${n}" 2>/dev/null)
		printf "  %-12s %-7s %-22s %-16s %b (restarts:%s)\n" "$n" "$role" "$peer" "${lports:--}" "$state" "${restarts:-0}" >&2
	done
	echo -e "${BLUE}=================================================================${NC}\n" >&2
}

remove_instance() {
	local inst="${1:-}"
	if [[ -z "$inst" ]]; then list_instances; inst=$(ask "Instance to remove: " ""); fi
	[[ -n "$inst" ]] || return 1
	[[ -f "$META_DIR/${inst}.meta" ]] || { log_err "Unknown instance: $inst"; return 1; }
	confirm "Remove instance '$inst' (service, config, firewall rules)?" "n" || return 1
	systemctl disable --now "paqet@${inst}" >/dev/null 2>&1 || true
	rm -f "$CONFIG_DIR/${inst}.yaml" "$META_DIR/${inst}.meta" "$STATE_DIR/${inst}."* 2>/dev/null
	apply_firewall            # rules are rebuilt from the remaining metadata
	systemctl daemon-reload
	log_ok "Instance '$inst' removed."
}

show_instance_key() {
	local inst="${1:-}"
	[[ -z "$inst" ]] && { list_instances; inst=$(ask "Instance: " ""); }
	[[ -f "$META_DIR/${inst}.meta" ]] || { log_err "Unknown instance."; return 1; }
	echo -e "  name   : ${BOLD}${inst}${NC}" >&2
	echo -e "  role   : $(meta_get "$inst" ROLE)" >&2
	echo -e "  peer   : $(meta_get "$inst" REMOTE_IP):$(meta_get "$inst" REMOTE_PORT)$(meta_get "$inst" PORT)" >&2
	echo -e "  key    : ${YELLOW}$(meta_get "$inst" KEY)${NC}" >&2
	echo -e "  mtu    : $(meta_get "$inst" MTU)   profile: $(meta_get "$inst" PROFILE)   conn: $(meta_get "$inst" CONN)" >&2
}

# Show panel/proxy ports listening on this box (useful on the exit node)
xui_ports() {
	have ss || { log_warn "iproute2 missing."; return 1; }
	echo -e "\n${BOLD}Listening proxy/panel sockets:${NC}" >&2
	ss -lntp 2>/dev/null | grep -Ei 'xray|x-ui|sing-box|hysteria|v2ray|trojan|haproxy|nginx' | sed 's/^/  /' >&2 \
		|| log_warn "No known panel process is listening."
}

#-------------------------------------------------------------------------------
# Diagnostics
#-------------------------------------------------------------------------------
fw_counter_in() { # fw_counter_in <remote_ip> <remote_port> -> inbound packet count
	iptables -t raw -L PAQQET_RAW_PRE -v -n -x 2>/dev/null \
		| awk -v ip="$1" -v p="spt:$2" '$0 ~ ip && $0 ~ p {gsub(/,/,"",$1); s+=$1} END {print s+0}'
}

run_diagnostics() {
	echo -e "\n${BOLD}${BLUE}============== paQQet DIAGNOSTICS ==============${NC}" >&2
	if [[ -x "$BIN_PATH" ]]; then
		log_ok "core: $("$BIN_PATH" version 2>/dev/null | sed -n '1p')"
	else
		log_err "core: paqet binary NOT installed"
	fi
	systemctl is-enabled paqqet-firewall.service >/dev/null 2>&1 && log_ok "firewall unit enabled" || log_warn "firewall unit not enabled"
	local nrules
	nrules=$(iptables -t raw -S PAQQET_RAW_PRE 2>/dev/null | grep -c -- '-A' || true)
	log_info "raw PREROUTING rules in PAQQET chain: ${nrules:-0}"
	[[ -f "$STRICT_FILE" ]] && log_info "strict INPUT drop: $(cat "$STRICT_FILE")"

	local names; mapfile -t names < <(instance_names)
	((${#names[@]})) || { log_warn "No instances configured."; return 0; }

	local n role svc rip rport mtu lports lp
	for n in "${names[@]}"; do
		role=$(meta_get "$n" ROLE); svc="paqet@${n}"
		echo -e "\n${BOLD}--- ${n} (${role}) ---${NC}" >&2
		if systemctl is-active --quiet "$svc"; then
			log_ok "service active since $(systemctl show -p ActiveEnterTimestamp --value "$svc" 2>/dev/null)"
		else
			log_err "service NOT active ($(systemctl is-active "$svc" 2>/dev/null))"
			journalctl -u "$svc" -n 10 --no-pager 2>/dev/null | sed 's/^/      /' >&2
		fi
		if [[ "$role" == "client" ]]; then
			rip=$(meta_get "$n" REMOTE_IP); rport=$(meta_get "$n" REMOTE_PORT); mtu=$(meta_get "$n" MTU)
			local c1 c2
			c1=$(fw_counter_in "$rip" "$rport"); sleep 4; c2=$(fw_counter_in "$rip" "$rport")
			if (( c2 > c1 )); then
				log_ok "inbound tunnel packets from ${rip}:${rport}: +$((c2-c1)) in 4s (link is alive)"
			else
				log_err "NO inbound packets from ${rip}:${rport} in 4s -> exit node down, port filtered, or key/flag mismatch"
			fi
			if ping -c 1 -W 2 -M do -s $((mtu>0 ? mtu-28 : 1322)) "$rip" >/dev/null 2>&1; then
				log_ok "path MTU >= ${mtu} towards ${rip}"
			else
				log_warn "ICMP probe of size ${mtu} failed (ICMP may be filtered; lower MTU if the tunnel stalls)"
			fi
			lports=$(meta_get "$n" LOCAL_PORTS)
			for lp in ${lports//,/ }; do
				[[ -z "$lp" ]] && continue
				if port_in_use "$lp" tcp; then log_ok "local listener ${lp}/tcp is up"; else log_warn "local port ${lp} is not listening"; fi
			done
		else
			local p; p=$(meta_get "$n" PORT)
			iptables -t raw -S PAQQET_RAW_PRE 2>/dev/null | grep -q -- "--dport $p" \
				&& log_ok "NOTRACK rule present for :$p" || log_err "NOTRACK rule MISSING for :$p (run Apply firewall)"
			port_in_use "$p" tcp && log_err "Another process holds TCP :$p - it will break the raw tunnel" || log_ok "port :$p free of kernel sockets (correct)"
		fi
	done
	echo -e "\n${BLUE}================================================${NC}" >&2
}

live_monitor() {
	local names; mapfile -t names < <(instance_names)
	((${#names[@]})) || { log_warn "No instances."; return 0; }
	list_instances
	local inst; inst=$(ask "Instance to monitor: " "${names[0]}")
	[[ -f "$META_DIR/${inst}.meta" ]] || { log_err "Unknown instance."; return 1; }
	echo -e "1) journal (live)\n2) tcpdump on the tunnel flow\n3) paqet dump (server role only)" >&2
	local c; c=$(ask "Choice [1]: " "1")
	case "$c" in
		2)
			have tcpdump || { log_err "tcpdump is not installed."; return 1; }
			local iface filt
			iface=$(meta_get "$inst" IFACE)
			if [[ "$(meta_get "$inst" ROLE)" == "client" ]]; then
				filt="host $(meta_get "$inst" REMOTE_IP) and tcp port $(meta_get "$inst" REMOTE_PORT)"
			else
				filt="tcp port $(meta_get "$inst" PORT)"
			fi
			log_info "tcpdump -i $iface $filt   (Ctrl+C to stop)"
			tcpdump -ni "$iface" -c 200 $filt 2>&1 | sed 's/^/  /' >&2 ;;
		3)
			[[ "$(meta_get "$inst" ROLE)" == "server" ]] || { log_err "'paqet dump' expects a server config."; return 1; }
			"$BIN_PATH" dump -c "$CONFIG_DIR/${inst}.yaml" ;;
		*)
			journalctl -u "paqet@${inst}" -f -n 60 --no-pager ;;
	esac
}

#-------------------------------------------------------------------------------
# Watchdog
# NOTE: 'paqet ping' only SENDS a probe packet, it does not wait for an answer,
# so it can never prove that a tunnel is alive. The real health signal used here
# is the inbound packet counter of the per-instance raw-table rule: smux
# keepalives guarantee traffic on a healthy link, so a zero delta while the
# service is running means the tunnel is dead (exit down / port filtered).
#-------------------------------------------------------------------------------
write_watchdog() {
	cat > "$WD_SCRIPT" << 'WDEOF'
#!/usr/bin/env bash
# Generated by paQQet - health monitor for paqet tunnel instances
set -o pipefail
META_DIR="/etc/paqet/meta"
STATE_DIR="/var/lib/paqqet"
LOG="/var/log/paqqet-watchdog.log"
FAIL_THRESHOLD="${PAQQET_WD_FAILS:-2}"      # consecutive bad checks before restart
COOLDOWN="${PAQQET_WD_COOLDOWN:-600}"       # min seconds between restarts of one instance
MAX_LOG_LINES=2000

mkdir -p "$STATE_DIR"
log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

counter_in() { # <ip> <port>
	iptables -t raw -L PAQQET_RAW_PRE -v -n -x 2>/dev/null \
		| awk -v ip="$1" -v p="spt:$2" '$0 ~ ip && $0 ~ p {gsub(/,/,"",$1); s+=$1} END {print s+0}'
}
counter_srv() { # <port>
	iptables -t raw -L PAQQET_RAW_PRE -v -n -x 2>/dev/null \
		| awk -v p="dpt:$1" '$0 ~ p {gsub(/,/,"",$1); s+=$1} END {print s+0}'
}

restart_instance() { # <name> <reason>
	local n="$1" reason="$2" last now
	now=$(date +%s)
	last=$(cat "$STATE_DIR/${n}.last_restart" 2>/dev/null || echo 0)
	if (( now - last < COOLDOWN )); then
		log "[$n] unhealthy ($reason) but cooldown active ($((now-last))s < ${COOLDOWN}s)"
		return 0
	fi
	log "[$n] RESTART - $reason"
	systemctl restart "paqet@${n}" >/dev/null 2>&1
	echo "$now" > "$STATE_DIR/${n}.last_restart"
	echo 0 > "$STATE_DIR/${n}.fail"
}

shopt -s nullglob
for meta in "$META_DIR"/*.meta; do
	ROLE=""; PORT=""; REMOTE_IP=""; REMOTE_PORT=""; PROBE_CMD=""; SOCKS_PORT=""; SOCKS_BIND=""
	# shellcheck disable=SC1090
	. "$meta" 2>/dev/null || continue
	name="$(basename "$meta" .meta)"
	unit="paqet@${name}"

	systemctl is-enabled --quiet "$unit" 2>/dev/null || continue

	if ! systemctl is-active --quiet "$unit"; then
		restart_instance "$name" "service inactive"
		continue
	fi

	bad=0; why=""

	# 1) inbound packet delta (primary, end-to-end signal)
	if [[ "$ROLE" == "client" && -n "$REMOTE_IP" && -n "$REMOTE_PORT" ]]; then
		cur=$(counter_in "$REMOTE_IP" "$REMOTE_PORT")
		prev=$(cat "$STATE_DIR/${name}.pkts" 2>/dev/null || echo "")
		echo "$cur" > "$STATE_DIR/${name}.pkts"
		if [[ -n "$prev" ]] && (( cur <= prev )); then bad=1; why="no inbound packets from ${REMOTE_IP}:${REMOTE_PORT}"; fi
	elif [[ "$ROLE" == "server" && -n "$PORT" ]]; then
		cur=$(counter_srv "$PORT")
		echo "$cur" > "$STATE_DIR/${name}.pkts"
	fi

	# 2) optional real payload probe through a SOCKS5 listener
	if [[ $bad -eq 0 && -n "$SOCKS_PORT" ]] && command -v curl >/dev/null 2>&1; then
		if ! curl -s -m 10 --socks5-hostname "${SOCKS_BIND:-127.0.0.1}:${SOCKS_PORT}" -o /dev/null \
			"${PAQQET_WD_PROBE_URL:-http://cp.cloudflare.com/generate_204}"; then
			bad=1; why="socks5 probe failed"
		fi
	fi

	# 3) optional user-defined probe (PROBE_CMD="..." inside the .meta file)
	if [[ $bad -eq 0 && -n "$PROBE_CMD" ]]; then
		if ! timeout 15 bash -c "$PROBE_CMD" >/dev/null 2>&1; then bad=1; why="custom probe failed"; fi
	fi

	if (( bad )); then
		fails=$(( $(cat "$STATE_DIR/${name}.fail" 2>/dev/null || echo 0) + 1 ))
		echo "$fails" > "$STATE_DIR/${name}.fail"
		log "[$name] unhealthy ($why) [$fails/$FAIL_THRESHOLD]"
		(( fails >= FAIL_THRESHOLD )) && restart_instance "$name" "$why"
	else
		echo 0 > "$STATE_DIR/${name}.fail"
	fi
done

if [[ -f "$LOG" ]]; then
	lines=$(wc -l < "$LOG" 2>/dev/null || echo 0)
	if (( lines > MAX_LOG_LINES )); then tail -n $((MAX_LOG_LINES/2)) "$LOG" > "${LOG}.tmp" && mv -f "${LOG}.tmp" "$LOG"; fi
fi
exit 0
WDEOF
	chmod 0755 "$WD_SCRIPT"
	touch "$WD_LOG"; chmod 0640 "$WD_LOG"
}

watchdog_enable() {
	mkdir -p "$STATE_DIR"
	write_watchdog
	cat > "$WD_SERVICE" << EOF
[Unit]
Description=paQQet tunnel health check
After=network-online.target

[Service]
Type=oneshot
ExecStart=$WD_SCRIPT
EOF
	cat > "$WD_TIMER" << 'EOF'
[Unit]
Description=Run paQQet health check every 2 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=2min
AccuracySec=15s
RandomizedDelaySec=15s
Unit=paqqet-watchdog.service

[Install]
WantedBy=timers.target
EOF
	systemctl daemon-reload
	systemctl enable --now paqqet-watchdog.timer >/dev/null 2>&1
	log_ok "Watchdog enabled (every 2 min, log: $WD_LOG)."
}

watchdog_disable() {
	systemctl disable --now paqqet-watchdog.timer >/dev/null 2>&1 || true
	rm -f "$WD_SERVICE" "$WD_TIMER" "$WD_SCRIPT"
	systemctl daemon-reload
	log_ok "Watchdog disabled."
}

watchdog_menu() {
	local st="disabled"
	systemctl is-active --quiet paqqet-watchdog.timer && st="enabled"
	echo -e "\nWatchdog status: ${BOLD}${st}${NC}" >&2
	echo -e "1) Enable / reinstall\n2) Disable\n3) Run once now\n4) Show log\n0) Back" >&2
	case "$(ask 'Choice: ' '0')" in
		1) watchdog_enable ;;
		2) watchdog_disable ;;
		3) [[ -x "$WD_SCRIPT" ]] || write_watchdog; "$WD_SCRIPT"; tail -n 20 "$WD_LOG" 2>/dev/null | sed 's/^/  /' >&2 ;;
		4) tail -n 60 "$WD_LOG" 2>/dev/null | sed 's/^/  /' >&2 || log_warn "No log yet." ;;
	esac
}

#-------------------------------------------------------------------------------
# Optional HAProxy front-end: one public port -> many tunnels (TCP only)
#-------------------------------------------------------------------------------
loadbalancer_menu() {
	local names; mapfile -t names < <(instance_names)
	local clients=() n
	for n in "${names[@]}"; do [[ "$(meta_get "$n" ROLE)" == "client" ]] && clients+=("$n"); done
	((${#clients[@]} >= 1)) || { log_err "No client instances found."; return 1; }

	echo -e "\n${BOLD}Load balancer / failover across exit tunnels (TCP only)${NC}" >&2
	echo -e "UDP cannot be balanced by HAProxy - keep UDP on a single tunnel.\n" >&2
	local i=1
	for n in "${clients[@]}"; do echo "  $i) $n -> $(meta_get "$n" REMOTE_IP)  local ports: $(meta_get "$n" LOCAL_PORTS)"; i=$((i+1)); done >&2

	local pub mode sel
	pub=$(ask "Public service port on this Iran server (e.g. 2053): " "")
	valid_port "$pub" || { log_err "Invalid port."; return 1; }
	port_in_use "$pub" tcp && { log_err "Port $pub is already in use."; return 1; }
	mode=$(ask "Mode: 1=round-robin (share load)  2=failover (first alive) [1]: " "1")
	sel=$(ask "Instances to include (comma separated names, empty = all): " "")
	[[ -z "$sel" ]] && sel=$(IFS=,; echo "${clients[*]}")

	have haproxy || { log_info "Installing haproxy..."; pkg_install haproxy || { log_err "haproxy install failed."; return 1; }; }

	{
		echo "# Generated by paQQet - dedicated instance, does not touch /etc/haproxy/haproxy.cfg"
		echo "global"
		echo "    maxconn 200000"
		echo "    log /dev/log local0 notice"
		echo "defaults"
		echo "    mode tcp"
		echo "    timeout connect 5s"
		echo "    timeout client  300s"
		echo "    timeout server  300s"
		echo "    retries 2"
		echo "frontend paqqet_front"
		echo "    bind 0.0.0.0:${pub}"
		echo "    default_backend paqqet_back"
		echo "backend paqqet_back"
		if [[ "$mode" == "2" ]]; then echo "    balance first"; else echo "    balance roundrobin"; fi
		local idx=1 srv lp first_lp
		for srv in ${sel//,/ }; do
			[[ -f "$META_DIR/${srv}.meta" ]] || continue
			first_lp=$(meta_get "$srv" LOCAL_PORTS | cut -d, -f1)
			[[ -n "$first_lp" ]] || continue
			if [[ "$mode" == "2" && $idx -gt 1 ]]; then
				echo "    server ${srv} 127.0.0.1:${first_lp} check inter 5s fall 3 rise 2 backup"
			else
				echo "    server ${srv} 127.0.0.1:${first_lp} check inter 5s fall 3 rise 2"
			fi
			idx=$((idx+1))
		done
	} > "$LB_CONF"
	chmod 600 "$LB_CONF"

	cat > "$LB_SERVICE" << EOF
[Unit]
Description=paQQet HAProxy front-end for tunnel exits
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/sbin/haproxy -c -f $LB_CONF
ExecStart=/usr/sbin/haproxy -Ws -f $LB_CONF
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	systemctl enable --now paqqet-lb.service >/dev/null 2>&1
	sleep 2
	if systemctl is-active --quiet paqqet-lb.service; then
		log_ok "Load balancer active on 0.0.0.0:${pub} -> ${sel}"
	else
		log_err "paqqet-lb failed to start:"; journalctl -u paqqet-lb -n 15 --no-pager | sed 's/^/  /' >&2
	fi
}

#-------------------------------------------------------------------------------
# DNS (systemd-resolved aware)
#-------------------------------------------------------------------------------
dns_menu() {
	echo -e "\n1) Cloudflare (1.1.1.1)\n2) Google (8.8.8.8)\n3) Shecan (178.22.122.100) - Iran only\n4) Restore backup\n0) Back" >&2
	local c s1 s2; c=$(ask 'Choice: ' '0')
	case "$c" in
		1) s1="1.1.1.1"; s2="1.0.0.1" ;;
		2) s1="8.8.8.8"; s2="8.8.4.4" ;;
		3) s1="178.22.122.100"; s2="185.51.200.2" ;;
		4)
			if [[ -f /etc/resolv.conf.paqqet.bak ]]; then
				chattr -i /etc/resolv.conf 2>/dev/null || true
				cp -f /etc/resolv.conf.paqqet.bak /etc/resolv.conf; log_ok "resolv.conf restored."
			else log_warn "No backup found."; fi
			return 0 ;;
		*) return 0 ;;
	esac
	if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
		mkdir -p /etc/systemd/resolved.conf.d
		printf '[Resolve]\nDNS=%s %s\nFallbackDNS=9.9.9.9\n' "$s1" "$s2" > /etc/systemd/resolved.conf.d/99-paqqet.conf
		systemctl restart systemd-resolved
		log_ok "systemd-resolved DNS set to $s1, $s2"
	else
		[[ -f /etc/resolv.conf && ! -f /etc/resolv.conf.paqqet.bak ]] && cp -f /etc/resolv.conf /etc/resolv.conf.paqqet.bak
		chattr -i /etc/resolv.conf 2>/dev/null || true
		printf 'nameserver %s\nnameserver %s\noptions timeout:2 attempts:2\n' "$s1" "$s2" > /etc/resolv.conf
		confirm "Lock /etc/resolv.conf against overwrites (chattr +i)?" "n" && chattr +i /etc/resolv.conf 2>/dev/null || true
		log_ok "DNS set to $s1, $s2"
	fi
}

#-------------------------------------------------------------------------------
# Backup / restore / uninstall
#-------------------------------------------------------------------------------
backup_now() {
	local f="$BACKUP_DIR/paqqet-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
	tar -czf "$f" \
		--ignore-failed-read \
		-C / \
		etc/paqet \
		$( [[ -f "$SERVICE_TEMPLATE" ]] && echo etc/systemd/system/paqet@.service ) \
		$( [[ -f "$FW_SERVICE" ]] && echo etc/systemd/system/paqqet-firewall.service ) \
		$( [[ -f "$SYSCTL_CONF" ]] && echo etc/sysctl.d/99-paqqet.conf ) 2>/dev/null
	chmod 600 "$f"
	log_ok "Backup written to $f (contains secret keys - keep it private)."
}

restore_backup() {
	local f="${1:-}"
	[[ -z "$f" ]] && f=$(ask "Path to backup .tar.gz: " "")
	[[ -f "$f" ]] || { log_err "File not found: $f"; return 1; }
	tar -tzf "$f" | grep -qE '^(/|\.\./)' && { log_err "Refusing archive with absolute/traversal paths."; return 1; }
	tar -xzf "$f" -C /
	chmod 700 "$CONFIG_DIR" "$META_DIR" 2>/dev/null || true
	chmod 600 "$CONFIG_DIR"/*.yaml "$META_DIR"/*.meta 2>/dev/null || true
	install_service_template
	apply_firewall
	local n
	while read -r n; do [[ -n "$n" ]] && systemctl enable --now "paqet@${n}" >/dev/null 2>&1; done < <(instance_names)
	systemctl daemon-reload
	log_ok "Restore finished."
	list_instances
}

uninstall_all() {
	confirm "Remove ALL paQQet tunnels, services, rules and the paqet binary?" "n" || return 0
	local n
	while read -r n; do
		[[ -n "$n" ]] || continue
		systemctl disable --now "paqet@${n}" >/dev/null 2>&1 || true
	done < <(instance_names)
	systemctl disable --now paqqet-lb.service >/dev/null 2>&1 || true
	watchdog_disable
	remove_firewall_all
	rm -f "$SERVICE_TEMPLATE" "$LB_SERVICE" "$SYSCTL_CONF" "$LIMITS_CONF" "$MODULES_CONF"
	rm -rf "$CONFIG_DIR" "$STATE_DIR"
	rm -f "$BIN_PATH" "$SELF_PATH" "$WD_LOG"
	systemctl daemon-reload
	sysctl --system >/dev/null 2>&1 || true
	log_ok "paQQet fully removed. Backups in $BACKUP_DIR were kept."
}

toggle_strict() {
	if [[ "$STRICT_FW" == "1" ]]; then
		STRICT_FW=0
		log_ok "Strict mode OFF: the kernel still sees tunnel packets (RST-drop + NOTRACK stay active)."
	else
		STRICT_FW=1
		log_ok "Strict mode ON: tunnel packets are dropped in INPUT so the kernel can never answer them."
	fi
	apply_firewall
}

#-------------------------------------------------------------------------------
# Interactive menu
#-------------------------------------------------------------------------------
show_banner() {
	local core="not installed" ninst
	[[ -x "$BIN_PATH" ]] && core="$("$BIN_PATH" version 2>/dev/null | sed -n '1p')"
	[[ -z "$core" ]] && core="installed"
	ninst=$(instance_names | wc -l)
	echo -e "${BOLD}${MAGENTA}" >&2
	echo "  +-----------------------------------------------------------+" >&2
	echo "  |   paQQet ${SCRIPT_VERSION}  -  multi-exit raw-packet tunnel manager |" >&2
	echo "  |   IRAN HUB  ==KCP over raw TCP==>  N EXIT SERVERS         |" >&2
	echo "  +-----------------------------------------------------------+" >&2
	echo -e "${NC}" >&2
	echo -e "   core: ${CYAN}${core}${NC}    instances: ${CYAN}${ninst}${NC}    strict-fw: ${CYAN}${STRICT_FW}${NC}" >&2
	echo "" >&2
}

menu() {
	while true; do
		show_banner
		cat >&2 << 'MEOF'
   1) Install / update paqet core (safe for running tunnels)
   2) Configure THIS server as an EXIT node        (abroad / kharej)
   3) Add an exit tunnel to THIS server            (Iran hub / client)
   4) Batch wizard: add several exit nodes at once (Iran hub)
  ------------------------------------------------------------------
   5) List instances                 6) Diagnostics
   7) Live monitor / logs            8) Watchdog
   9) Apply kernel + NIC tuning     10) Rebuild firewall rules
  11) Show instance key / params    12) Load balancer (HAProxy)
  13) DNS settings                  14) Backup / restore
  15) Show panel ports (3X-UI/Xray) 16) Remove an instance
  17) Toggle strict firewall mode   18) Uninstall everything
   0) Exit
MEOF
		local c; c=$(ask "$(echo -e "\n  ${BOLD}Choice:${NC} ")" "0")
		case "$c" in
			1) ensure_deps; install_core "latest" ;;
			2)
				local n p k m pr cn wd
				n=$(ask "Instance name [server]: " "server")
				p=$(ask "Tunnel listen port [${DEF_EXIT_PORT}]: " "$DEF_EXIT_PORT")
				k=$(ask "Secret key (empty = generate): " "")
				pr=$(ask "KCP profile (fast3/fast2/fast/normal/lowlatency/bandwidth) [${DEF_PROFILE}]: " "$DEF_PROFILE")
				m=$(ask "MTU [${DEF_MTU}]: " "$DEF_MTU")
				cn=$(ask "Parallel KCP connections [${DEF_CONN}]: " "$DEF_CONN")
				wd=$(ask "KCP window [${DEF_WND}]: " "$DEF_WND")
				configure_server "$n" "$p" "$k" "$m" "$pr" "$cn" "$wd" ;;
			3) client_wizard ;;
			4) multi_exit_wizard ;;
			5) list_instances ;;
			6) run_diagnostics ;;
			7) live_monitor ;;
			8) watchdog_menu ;;
			9) detect_network_details; apply_linux_optimizations ;;
			10) apply_firewall ;;
			11) show_instance_key ;;
			12) loadbalancer_menu ;;
			13) dns_menu ;;
			14)
				echo -e "  1) Backup now\n  2) Restore from file" >&2
				case "$(ask 'Choice: ' '1')" in 1) backup_now ;; 2) restore_backup ;; esac ;;
			15) xui_ports ;;
			16) remove_instance ;;
			17) toggle_strict ;;
			18) uninstall_all; exit 0 ;;
			0) exit 0 ;;
			*) log_warn "Invalid choice." ;;
		esac
		pause_prompt
	done
}

#-------------------------------------------------------------------------------
# Non-interactive CLI
#-------------------------------------------------------------------------------
usage() {
	cat >&2 << EOF
paQQet ${SCRIPT_VERSION} - multi-exit raw-packet tunnel manager

Usage: paQQet <command> [options]

Commands:
  install [version]              Install or update the paqet core (default: latest)
  server  [options]              Configure this host as an EXIT node
    --name N --port P [--key K] [--mtu 1350] [--profile fast3] [--conn 4] [--wnd 2048]
  client  [options]              Add an exit tunnel on the Iran hub
    --name N --remote IP --port P --key K
    [--ports "2053,8080>443,9000>10.0.0.5:9000"] [--bind 0.0.0.0] [--proto tcp|udp|both]
    [--socks5 1080 [--socks-user U --socks-pass P]] [--mtu] [--profile] [--conn] [--wnd]
  list | status                  Show all instances
  test | diag                    Run diagnostics
  optimize                       Apply kernel/NIC tuning
  fw-apply                       Rebuild the paQQet firewall chains
  watchdog on|off|run            Manage the health watchdog
  lb                             Configure the HAProxy front-end
  backup | restore <file>        Backup or restore the configuration
  remove <instance>              Delete one instance
  uninstall                      Remove everything
  version | help

Environment overrides:
  PAQQET_IFACE, PAQQET_LOCAL_IP, PAQQET_ROUTER_MAC, PAQQET_STRICT_FW=0|1,
  PAQQET_ASSUME_YES=1, PAQET_VERSION, PAQQET_TCP_FLAG, PAQQET_BLOCK

Examples:
  # exit node (abroad)
  paQQet install && paQQet server --name de1 --port 9443
  # Iran hub -> two exits, one instance each
  paQQet client --name de1 --remote 1.2.3.4 --port 9443 --key XXX --ports 2053
  paQQet client --name nl1 --remote 5.6.7.8 --port 9443 --key YYY --ports 2054>2053
EOF
}

cli_server() {
	local name="server" port="$DEF_EXIT_PORT" key="" mtu="$DEF_MTU" prof="$DEF_PROFILE" conn="$DEF_CONN" wnd="$DEF_WND"
	while (($#)); do
		case "$1" in
			--name)    name="$2"; shift 2 ;;
			--port)    port="$2"; shift 2 ;;
			--key)     key="$2"; shift 2 ;;
			--mtu)     mtu="$2"; shift 2 ;;
			--profile) prof="$2"; shift 2 ;;
			--conn)    conn="$2"; shift 2 ;;
			--wnd)     wnd="$2"; shift 2 ;;
			--yes|-y)  ASSUME_YES=1; shift ;;
			*) die "Unknown option: $1" ;;
		esac
	done
	configure_server "$name" "$port" "$key" "$mtu" "$prof" "$conn" "$wnd"
}

cli_client() {
	reset_client_vars
	while (($#)); do
		case "$1" in
			--name)       C_NAME="$2"; shift 2 ;;
			--remote)     C_REMOTE="$2"; shift 2 ;;
			--port)       C_PORT="$2"; shift 2 ;;
			--key)        C_KEY="$2"; shift 2 ;;
			--ports)      C_PORTS="$2"; shift 2 ;;
			--bind)       C_BIND="$2"; shift 2 ;;
			--proto)      C_PROTO="$2"; shift 2 ;;
			--socks5)     C_SOCKS="$2"; shift 2 ;;
			--socks-user) C_SOCKS_USER="$2"; shift 2 ;;
			--socks-pass) C_SOCKS_PASS="$2"; shift 2 ;;
			--mtu)        C_MTU="$2"; shift 2 ;;
			--profile)    C_PROF="$2"; shift 2 ;;
			--conn)       C_CONN="$2"; shift 2 ;;
			--wnd)        C_WND="$2"; shift 2 ;;
			--yes|-y)     ASSUME_YES=1; shift ;;
			*) die "Unknown option: $1" ;;
		esac
	done
	case "$C_PROTO" in tcp|udp|both) ;; *) die "--proto must be tcp, udp or both" ;; esac
	configure_client
}

main() {
	need_root
	mkdir -p "$CONFIG_DIR" "$META_DIR" "$STATE_DIR" 2>/dev/null || true
	chmod 700 "$CONFIG_DIR" "$META_DIR" 2>/dev/null || true
	if [[ -z "${PAQQET_STRICT_FW:-}" && -f "$STRICT_FILE" ]]; then
		STRICT_FW=$(head -n1 "$STRICT_FILE" 2>/dev/null || echo 1)
	fi

	local cmd="${1:-}"
	[[ $# -gt 0 ]] && shift
	case "$cmd" in
		install)        ensure_deps; install_core "${1:-latest}" ;;
		server)         ensure_deps; cli_server "$@" ;;
		client)         ensure_deps; cli_client "$@" ;;
		list|status)    list_instances ;;
		test|diag)      run_diagnostics ;;
		optimize)       detect_network_details; apply_linux_optimizations ;;
		fw-apply)       apply_firewall ;;
		watchdog)
			case "${1:-}" in
				on)  watchdog_enable ;;
				off) watchdog_disable ;;
				run) [[ -x "$WD_SCRIPT" ]] || write_watchdog; "$WD_SCRIPT" ;;
				*)   watchdog_menu ;;
			esac ;;
		lb)             loadbalancer_menu ;;
		backup)         backup_now ;;
		restore)        restore_backup "${1:-}" ;;
		remove)         remove_instance "${1:-}" ;;
		uninstall)      uninstall_all ;;
		key)            show_instance_key "${1:-}" ;;
		version|-v|--version) echo "paQQet ${SCRIPT_VERSION}" ;;
		help|-h|--help) usage ;;
		"")             ensure_deps; menu ;;
		*)              log_err "Unknown command: $cmd"; usage; exit 1 ;;
	esac
}

main "$@"
