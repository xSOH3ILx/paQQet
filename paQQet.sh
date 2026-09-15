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

SCRIPT_VERSION="4.4.0"
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
DEF_PROFILE="${PAQQET_PROFILE:-iran}"
DEF_WND="${PAQQET_WND:-1024}"                  # rcvwnd/sndwnd (1-32768)
DEF_BLOCK="${PAQQET_BLOCK:-aes}"
SEL_BLOCK="${PAQQET_BLOCK:-aes}"      # selected cipher (menu / --block)
PICKED_PROFILE=""; SUG_WND=""; SUG_CONN=""
PICK_REMOTE=""; PICK_MTU=""; PICK_CONN=""; CHOOSE_FREE=0
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
valid_profile() { [[ "$1" =~ ^(normal|fast|fast2|fast3|lowlatency|bandwidth|iran|iran-max|iran-game)$ ]]; }

#-------------------------------------------------------------------------------
# Numeric pickers: nothing has to be typed, every choice is a number.
# choose <default_value> <title> <value|label|description>...
#-------------------------------------------------------------------------------
choose() {
	local def="$1" title="$2"; shift 2
	local item v l d ans i=1 n=$#
	local -a vals=()
	echo -e "\n${BOLD}${BLUE}${title}${NC}" >&2
	for item in "$@"; do
		IFS='|' read -r v l d <<< "$item"
		vals+=("$v")
		if [[ "$v" == "$def" ]]; then
			printf '  %b%2d)%b %-11s %s %b<= current%b\n' "$BOLD" "$i" "$NC" "$l" "$d" "$GREEN" "$NC" >&2
		else
			printf '  %b%2d)%b %-11s %s\n' "$BOLD" "$i" "$NC" "$l" "$d" >&2
		fi
		i=$((i+1))
	done
	ans=$(ask "  Select 1-${n} (Enter = ${def}): " "")
	[[ -z "$ans" ]] && { printf '%s\n' "$def"; return 0; }
	if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans >= 1 && ans <= n )); then
		printf '%s\n' "${vals[$((ans-1))]}"; return 0
	fi
	for v in "${vals[@]}"; do [[ "$ans" == "$v" ]] && { printf '%s\n' "$v"; return 0; }; done
	if [[ "${CHOOSE_FREE:-0}" == "1" ]]; then printf '%s\n' "$ans"; return 0; fi
	log_warn "Invalid choice '$ans' - using ${def}."
	printf '%s\n' "$def"
}

# same as choose, but a typed value that is not in the list is accepted as-is
choose_free() { CHOOSE_FREE=1; choose "$@"; CHOOSE_FREE=0; }

profile_sug_wnd() {
	case "$1" in
		iran) echo 1024 ;;
		iran-max) echo 2048 ;;
		iran-game) echo 256 ;;
		bandwidth) echo 2048 ;;
		lowlatency) echo 512 ;;
		*) echo "$DEF_WND" ;;
	esac
}

profile_sug_conn() {
	case "$1" in
		iran) echo 4 ;;
		iran-max) echo 8 ;;
		iran-game) echo 2 ;;
		*) echo "$DEF_CONN" ;;
	esac
}

# pick_profile [default] -> sets PICKED_PROFILE, SUG_WND, SUG_CONN (call it directly,
# not inside $( ), so the suggestions survive)
pick_profile() {
	local def="${1:-$DEF_PROFILE}"
	PICKED_PROFILE=$(choose "$def" "KCP profile - how the tunnel engine paces packets" \
		"iran|iran|balanced IR<->EU: good download AND upload, congestion control ON (recommended)" \
		"iran-max|iran-max|max throughput for heavy downloads, ~10-20ms more latency" \
		"iran-game|iran-game|lowest ping for gaming/voice, less throughput" \
		"fast3|fast3|stock, most aggressive: floods a lossy line, speed often collapses" \
		"fast2|fast2|stock, aggressive" \
		"fast|fast|stock, moderate" \
		"normal|normal|stock, gentle: lowest CPU and overhead" \
		"lowlatency|lowlatency|manual preset: 10ms tick, congestion control OFF" \
		"bandwidth|bandwidth|manual preset: bulk transfer, highest latency")
	SUG_WND=$(profile_sug_wnd "$PICKED_PROFILE")
	SUG_CONN=$(profile_sug_conn "$PICKED_PROFILE")
	printf '%s\n' "$PICKED_PROFILE"
}

# pick_cipher [default] -> sets SEL_BLOCK (payload encryption; must match on both sides)
pick_cipher() {
	local def="${1:-${SEL_BLOCK:-$DEF_BLOCK}}"
	SEL_BLOCK=$(choose "$def" "Tunnel encryption (same value required on both sides)" \
		"aes|aes|AES-256: strongest, ~1-3% CPU with AES-NI (recommended)" \
		"aes-128|aes-128|AES-128: same security class, faster on weak CPUs" \
		"salsa20|salsa20|Salsa20: fastest on ARM / old CPUs, good security" \
		"twofish|twofish|Twofish: alternative block cipher" \
		"blowfish|blowfish|Blowfish: legacy, low CPU" \
		"3des|3des|Triple DES: slow, compatibility only" \
		"cast5|cast5|CAST5: legacy" \
		"xor|xor|XOR: obfuscation only, NOT real encryption" \
		"none|none|no encryption: fastest, payload readable on the wire")
	printf '%s\n' "$SEL_BLOCK"
}

pick_proto() {
	choose "${1:-tcp}" "Which protocol should be forwarded" \
		"tcp|tcp|TCP only: panels, web, Xray TCP/WS/gRPC inbounds" \
		"udp|udp|UDP only: WireGuard, QUIC/Hysteria, DNS, game traffic" \
		"both|both|TCP + UDP on the same ports (two forward rules per port)"
}

pick_mtu() {
	choose_free "${1:-$DEF_MTU}" "KCP MTU (the outer packet is ~40 bytes bigger)" \
		"1350|1350|safe default, works on nearly every Iranian line" \
		"1400|1400|slightly more efficient, needs a clean 1440+ path" \
		"1300|1300|PPPoE / extra encapsulation on the way" \
		"1200|1200|very lossy or mobile links, most robust"
}

pick_conn() {
	choose_free "${1:-${SUG_CONN:-$DEF_CONN}}" "Parallel KCP connections (more = more speed, more CPU)" \
		"1|1|single link, lowest CPU" \
		"2|2|light usage" \
		"4|4|balanced: one panel / small user group" \
		"8|8|many users or heavy downloads" \
		"16|16|busy hub, needs CPU headroom"
}

pick_wnd() {
	local v
	v=$(choose_free "${1:-${SUG_WND:-$DEF_WND}}" "KCP window in packets (in-flight buffer: too big = bufferbloat + loss)" \
		"256|256|slow lines, snappiest latency" \
		"512|512|up to ~50 Mbit at 100ms RTT" \
		"1024|1024|~100 Mbit at 100ms RTT (recommended)" \
		"2048|2048|200 Mbit+ or bulk downloads" \
		"4096|4096|very fast links with plenty of RAM" \
		"auto|auto|compute it from line speed + measured RTT")
	[[ "$v" == "auto" ]] && v=$(auto_wnd)
	printf '%s\n' "$v"
}

# auto_wnd -> window per connection from the bandwidth-delay product
auto_wnd() {
	local mbps rtt mtu conn bdp w
	mbps=$(choose_free "100" "Line speed towards the exit server" \
		"10|10 Mbit|ADSL or weak mobile" \
		"30|30 Mbit|typical VDSL" \
		"50|50 Mbit|good VDSL / FTTH" \
		"100|100 Mbit|FTTH / datacenter" \
		"200|200 Mbit|fast datacenter" \
		"500|500 Mbit|premium datacenter" \
		"1000|1000 Mbit|1 Gbit uplink")
	rtt=""
	if [[ -n "${PICK_REMOTE:-}" ]]; then
		rtt=$(ping -c 3 -W 2 "$PICK_REMOTE" 2>/dev/null | awk -F'/' '/min\/avg|rtt|round-trip/ {print int($5)}' | tail -n1)
		[[ -n "$rtt" ]] && log_info "measured RTT to ${PICK_REMOTE}: ${rtt} ms"
	fi
	if [[ -z "$rtt" || "$rtt" == "0" ]]; then
		rtt=$(choose_free "100" "Round-trip time to the exit server (ms)" \
			"40|40 ms|Turkey / UAE / nearby" \
			"70|70 ms|Germany / Netherlands, good route" \
			"100|100 ms|Europe, typical" \
			"150|150 ms|congested Europe / US east" \
			"220|220 ms|US west / Asia")
	fi
	mtu="${PICK_MTU:-$DEF_MTU}"; conn="${PICK_CONN:-$DEF_CONN}"
	[[ "$mtu" =~ ^[0-9]+$ ]] || mtu="$DEF_MTU"
	[[ "$conn" =~ ^[0-9]+$ ]] || conn="$DEF_CONN"
	bdp=$(( mbps * 125000 * rtt / 1000 ))
	w=$(( bdp * 2 / mtu / conn ))
	(( w < 256 )) && w=256
	(( w > 8192 )) && w=8192
	log_info "auto window: ${mbps} Mbit, RTT ${rtt} ms, conn ${conn}, MTU ${mtu} -> ${w} packets per connection"
	printf '%s\n' "$w"
}

# pick_instance [role] -> echoes the chosen instance name
pick_instance() {
	local want="${1:-}" n role
	local -a names=() list=()
	mapfile -t names < <(instance_names)
	for n in "${names[@]}"; do
		role=$(meta_get "$n" ROLE)
		[[ -n "$want" && "$role" != "$want" ]] && continue
		if [[ "$role" == "server" ]]; then
			list+=("${n}|${n}|exit node, listening on :$(meta_get "$n" PORT)")
		else
			list+=("${n}|${n}|client -> $(meta_get "$n" REMOTE_IP):$(meta_get "$n" REMOTE_PORT) [$(meta_get "$n" PROFILE)]")
		fi
	done
	((${#list[@]})) || { log_err "No matching instance found."; return 1; }
	choose "${list[0]%%|*}" "Select an instance" "${list[@]}"
}

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
	local key="$1" mtu="$2" prof="$3" wnd="$4" blk="${SEL_BLOCK:-$DEF_BLOCK}"
	echo "  kcp:"
	case "$prof" in
		iran)
			# Custom IR<->EU balance: fast retransmit after 2 dup-ACKs, 20ms tick and
			# congestion control ON, so the Iranian uplink is not self-flooded.
			echo "    mode: \"manual\""
			echo "    nodelay: 1"
			echo "    interval: 20"
			echo "    resend: 2"
			echo "    nocongestion: 0"
			echo "    wdelay: false"
			echo "    acknodelay: false" ;;
		iran-max)
			# Throughput first: bigger tick + write delay batches more data per flush.
			echo "    mode: \"manual\""
			echo "    nodelay: 1"
			echo "    interval: 30"
			echo "    resend: 2"
			echo "    nocongestion: 0"
			echo "    wdelay: true"
			echo "    acknodelay: false" ;;
		iran-game)
			# Latency first: 10ms tick, immediate ACKs, congestion control off.
			echo "    mode: \"manual\""
			echo "    nodelay: 1"
			echo "    interval: 10"
			echo "    resend: 2"
			echo "    nocongestion: 1"
			echo "    wdelay: false"
			echo "    acknodelay: true" ;;
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
	echo "    block: \"${blk}\""
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

	write_meta "$name" "ROLE=server" "PORT=$port" "MTU=$mtu" "PROFILE=$prof" "BLOCK=${SEL_BLOCK:-$DEF_BLOCK}" "CONN=$conn" "WND=$wnd" \
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
	echo -e " Cipher      : ${CYAN}${SEL_BLOCK:-$DEF_BLOCK}${NC} (must match on both sides)" >&2
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
		"SOCKS_PORT=${C_SOCKS}" "SOCKS_BIND=${socks_bind}" "BIND=$bind" "MTU=$mtu" "PROFILE=$prof" "BLOCK=${SEL_BLOCK:-$DEF_BLOCK}" \
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
	PICK_REMOTE="$C_REMOTE"
	valid_ipv4 "$C_REMOTE" || { log_err "Invalid IPv4."; return 1; }
	C_PORT=$(ask "Exit tunnel port [${DEF_EXIT_PORT}]: " "$DEF_EXIT_PORT")
	C_KEY=$(ask "Secret key (from the exit node): " "")
	[[ -n "$C_KEY" ]] || { log_err "Key is required."; return 1; }

	echo -e "\n  Port mappings. Examples:  ${CYAN}2053,8443${NC}   ${CYAN}8080>443${NC}   ${CYAN}9000>10.0.0.5:9000${NC}" >&2
	C_PORTS=$(ask "Ports to tunnel (empty = SOCKS5 only): " "")
	local p; p=$(pick_proto "tcp")
	case "$p" in tcp|udp|both) C_PROTO="$p" ;; *) C_PROTO="tcp" ;; esac
	C_BIND=$(ask "Bind address for local listeners [0.0.0.0]: " "0.0.0.0")
	if confirm "Also expose a SOCKS5 proxy?" "n"; then
		C_SOCKS=$(ask "SOCKS5 port [1080]: " "1080")
		C_SOCKS_USER=$(ask "SOCKS5 username (empty = no auth, loopback only): " "")
		[[ -n "$C_SOCKS_USER" ]] && C_SOCKS_PASS=$(ask_secret "SOCKS5 password: ")
	fi
	pick_profile "$DEF_PROFILE" >/dev/null; C_PROF="$PICKED_PROFILE"
	pick_cipher "${SEL_BLOCK:-$DEF_BLOCK}" >/dev/null
	C_MTU=$(pick_mtu "$DEF_MTU")
	PICK_MTU="$C_MTU"
	C_CONN=$(pick_conn "${SUG_CONN:-$DEF_CONN}")
	PICK_CONN="$C_CONN"
	C_WND=$(pick_wnd "${SUG_WND:-$DEF_WND}")
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
	shared_proto=$(pick_proto "tcp")
	for ((i=1; i<=count; i++)); do
		echo -e "\n${BOLD}${MAGENTA}===== Exit node ${i}/${count} =====${NC}" >&2
		reset_client_vars
		C_NAME=$(ask "Name [exit${i}]: " "exit${i}")
		C_REMOTE=$(ask "Public IPv4: " "")
		PICK_REMOTE="$C_REMOTE"
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
	echo -e "  wnd    : $(meta_get "$inst" WND)   cipher: $(meta_get "$inst" BLOCK)" >&2
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
	local inst; inst=$(pick_instance)
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
#-------------------------------------------------------------------------------
# Re-tune an existing instance: profile / MTU / window / conn / cipher.
# Only the transport part of the config is rewritten, keys and ports stay.
#-------------------------------------------------------------------------------
retune_instance() {
	local inst="${1:-}"
	if [[ -z "$inst" ]]; then inst=$(pick_instance) || return 1; fi
	[[ -n "$inst" ]] || { log_err "No instance selected."; return 1; }
	local cfg="$CONFIG_DIR/${inst}.yaml"
	local meta="$META_DIR/${inst}.meta"
	[[ -f "$cfg" && -f "$meta" ]] || { log_err "Unknown instance: $inst"; return 1; }

	local cur_prof cur_mtu cur_wnd cur_conn cur_blk key
	cur_prof=$(meta_get "$inst" PROFILE)
	cur_mtu=$(meta_get "$inst" MTU)
	cur_wnd=$(meta_get "$inst" WND)
	cur_conn=$(meta_get "$inst" CONN)
	cur_blk=$(meta_get "$inst" BLOCK)
	key=$(meta_get "$inst" KEY)
	[[ -n "$cur_blk" ]] && SEL_BLOCK="$cur_blk"
	PICK_REMOTE=$(meta_get "$inst" REMOTE_IP)
	log_info "current: profile=${cur_prof} mtu=${cur_mtu} window=${cur_wnd} conn=${cur_conn} cipher=${cur_blk:-$DEF_BLOCK}"

	local prof mtu conn wnd
	pick_profile "${cur_prof:-$DEF_PROFILE}" >/dev/null; prof="$PICKED_PROFILE"
	pick_cipher "${cur_blk:-$DEF_BLOCK}" >/dev/null
	mtu=$(pick_mtu "${cur_mtu:-$DEF_MTU}"); PICK_MTU="$mtu"
	conn=$(pick_conn "${SUG_CONN:-${cur_conn:-$DEF_CONN}}"); PICK_CONN="$conn"
	wnd=$(pick_wnd "${SUG_WND:-${cur_wnd:-$DEF_WND}}")

	valid_profile "$prof" || { log_err "Invalid profile: $prof"; return 1; }
	valid_mtu "$mtu" || { log_err "Invalid MTU: $mtu"; return 1; }
	valid_conn "$conn" || { log_err "Invalid connection count: $conn"; return 1; }
	valid_wnd "$wnd" || { log_err "Invalid window: $wnd"; return 1; }

	cp -f "$cfg" "${cfg}.bak"
	local tmp
	tmp=$(mktemp) || return 1
	# the kcp: block is always the tail of a generated config
	sed -e "s/^  conn: .*/  conn: ${conn}/" "$cfg" | sed '/^  kcp:/,$d' > "$tmp"
	kcp_block "$key" "$mtu" "$prof" "$wnd" >> "$tmp"
	mv -f "$tmp" "$cfg"
	chmod 600 "$cfg"
	if ! validate_yaml "$cfg"; then
		cp -f "${cfg}.bak" "$cfg"
		log_err "The new config was rejected - rolled back, nothing changed."
		return 1
	fi

	sed -i -e "s/^PROFILE=.*/PROFILE=${prof}/" -e "s/^MTU=.*/MTU=${mtu}/" \
		-e "s/^WND=.*/WND=${wnd}/" -e "s/^CONN=.*/CONN=${conn}/" "$meta"
	if grep -q '^BLOCK=' "$meta"; then
		sed -i "s/^BLOCK=.*/BLOCK=${SEL_BLOCK:-$DEF_BLOCK}/" "$meta"
	else
		echo "BLOCK=${SEL_BLOCK:-$DEF_BLOCK}" >> "$meta"
	fi
	chmod 600 "$meta"

	log_ok "${inst}: profile=${prof} mtu=${mtu} window=${wnd} conn=${conn} cipher=${SEL_BLOCK:-$DEF_BLOCK}"
	start_instance "$inst" || return 1
	log_warn "The peer side must use exactly the same profile, MTU, window, conn and cipher."
	log_info "On the other server run:  paQQet retune ${inst}   (or menu option 19)"
}

#-------------------------------------------------------------------------------
# AUTO-PILOT (4.4.0)
#   probe this server + the route -> compute the best transport -> build it ->
#   print the exact command needed on the other server.
#-------------------------------------------------------------------------------
AP_IFACE=""
HW_CPU="unknown"; HW_CORES=1; HW_MEM=0; HW_AES=0; HW_VIRT="none"; HW_KERNEL=""
HW_NIC_DRV="unknown"; HW_NIC_SPEED=0; HW_QDISC="unknown"; HW_BBR=0; HW_CAKE=0
P_RTT=0; P_JIT=0; P_LOSS=0; P_MTU=0; P_ICMP=0; P_HOPS=0
P_TCP_STATE="unknown"; P_TCP_MS=0; P_PORT_STATE="unknown"; P_UDP_STATE="unknown"
BW_DOWN=0; BW_UP=0; BW_SRC="not measured"
PLAN_PROFILE="$DEF_PROFILE"; PLAN_MTU="$DEF_MTU"; PLAN_WND="$DEF_WND"; PLAN_CONN="$DEF_CONN"
PLAN_BLOCK="$DEF_BLOCK"; PLAN_PROTO="tcp"; PLAN_PURPOSE="balanced"
declare -a PLAN_NOTES=()

ap_note() { PLAN_NOTES+=("$1"); }
ap_int() { local v="${1:-0}"; v="${v%%.*}"; v="${v//[^0-9]/}"; [[ -n "$v" ]] || v=0; printf '%s\n' "$v"; }
ap_yn() { if (( ${1:-0} )); then echo yes; else echo no; fi; }

# ap_choose <title> <default-value> <value|label|description>...
ap_choose() {
	local title="$1" def="$2"; shift 2
	local item v l d ans i=1 n=$#
	local -a vals=()
	echo >&2
	echo -e "${BOLD}${BLUE}${title}${NC}" >&2
	for item in "$@"; do
		IFS='|' read -r v l d <<< "$item"
		vals+=("$v")
		if [[ "$v" == "$def" ]]; then
			printf '  %b%2d)%b %-13s %s %b<= default%b\n' "$BOLD" "$i" "$NC" "$l" "$d" "$GREEN" "$NC" >&2
		else
			printf '  %b%2d)%b %-13s %s\n' "$BOLD" "$i" "$NC" "$l" "$d" >&2
		fi
		i=$(( i + 1 ))
	done
	ans=$(ask "  Select 1-${n} (Enter = ${def}): " "")
	[[ -z "$ans" ]] && { printf '%s\n' "$def"; return 0; }
	if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans >= 1 && ans <= n )); then
		printf '%s\n' "${vals[$(( ans - 1 ))]}"; return 0
	fi
	for v in "${vals[@]}"; do [[ "$ans" == "$v" ]] && { printf '%s\n' "$v"; return 0; }; done
	printf '%s\n' "$def"
}

#--- 1. hardware, kernel, NIC --------------------------------------------------
hw_probe() {
	local s
	HW_CPU=$(awk -F: '/^model name/ { gsub(/^ +/, "", $2); print $2; exit }' /proc/cpuinfo 2>/dev/null)
	[[ -n "$HW_CPU" ]] || HW_CPU=$(uname -m)
	HW_CORES=$(nproc 2>/dev/null || echo 1)
	[[ "$HW_CORES" =~ ^[0-9]+$ ]] || HW_CORES=1
	HW_MEM=$(awk '/^MemTotal:/ { printf "%d", $2 / 1024 }' /proc/meminfo 2>/dev/null)
	[[ "$HW_MEM" =~ ^[0-9]+$ ]] || HW_MEM=0
	if grep -qiE '^flags.*[[:space:]]aes([[:space:]]|$)' /proc/cpuinfo 2>/dev/null; then HW_AES=1; else HW_AES=0; fi
	HW_KERNEL=$(uname -r 2>/dev/null)
	HW_VIRT="none"
	have systemd-detect-virt && HW_VIRT=$(systemd-detect-virt 2>/dev/null || echo none)
	AP_IFACE="${DETECTED_IFACE:-}"
	[[ -n "$AP_IFACE" ]] || AP_IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
	if [[ -n "$AP_IFACE" ]]; then
		HW_NIC_DRV=$(basename "$(readlink -f "/sys/class/net/${AP_IFACE}/device/driver" 2>/dev/null)" 2>/dev/null)
		[[ -n "$HW_NIC_DRV" && "$HW_NIC_DRV" != "." && "$HW_NIC_DRV" != "/" ]] || HW_NIC_DRV="unknown"
		s=$(cat "/sys/class/net/${AP_IFACE}/speed" 2>/dev/null)
		if [[ "$s" =~ ^[0-9]+$ ]]; then HW_NIC_SPEED=$s; else HW_NIC_SPEED=0; fi
		HW_QDISC=$(tc qdisc show dev "$AP_IFACE" 2>/dev/null | awk 'NR == 1 { print $2 }')
		[[ -n "$HW_QDISC" ]] || HW_QDISC="unknown"
	fi
	if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -qw bbr; then
		HW_BBR=1
	elif modprobe tcp_bbr >/dev/null 2>&1; then
		HW_BBR=1
	fi
	if grep -q '^sch_cake' /proc/modules 2>/dev/null || modinfo sch_cake >/dev/null 2>&1; then HW_CAKE=1; fi
	case "$HW_VIRT" in
		openvz|lxc|lxc-libvirt|docker|podman)
			ap_note "Virtualization is ${HW_VIRT}: raw packet capture/injection normally does not work there, KVM or bare metal is needed." ;;
	esac
	(( HW_MEM > 0 && HW_MEM < 700 )) && ap_note "Only ${HW_MEM} MB RAM: the window is kept small on purpose so the tunnel cannot be OOM-killed."
	if [[ -n "$AP_IFACE" ]] && ! ip -o link show dev "$AP_IFACE" 2>/dev/null | grep -q 'link/ether'; then
		ap_note "Interface ${AP_IFACE} has no MAC address (ppp/tun/venet): paqet builds Ethernet frames and cannot use it."
	fi
	return 0
}

#--- 2. the route --------------------------------------------------------------
# mtu_probe <ip> -> largest working path MTU (0 = ICMP filtered)
mtu_probe() {
	local ip="$1" lo=1000 hi=1472 mid best=0
	ping -n -M do -c 1 -W 2 -s 1472 "$ip" >/dev/null 2>&1 && { echo 1500; return 0; }
	ping -n -c 1 -W 2 "$ip" >/dev/null 2>&1 || { echo 0; return 0; }
	while (( lo <= hi )); do
		mid=$(( (lo + hi) / 2 ))
		if ping -n -M do -c 1 -W 2 -s "$mid" "$ip" >/dev/null 2>&1; then
			best=$mid; lo=$(( mid + 1 ))
		else
			hi=$(( mid - 1 ))
		fi
	done
	if (( best > 0 )); then echo $(( best + 28 )); else echo 0; fi
}

# tcp_probe <ip> <port> -> "open <ms>" | "closed <ms>" | "filtered <ms>"
tcp_probe() {
	local ip="$1" port="$2" t0 t1 ms
	t0=$(date +%s%N 2>/dev/null); [[ "$t0" =~ ^[0-9]+$ ]] || t0=0
	if timeout 4 bash -c "exec 3<>/dev/tcp/${ip}/${port}" >/dev/null 2>&1; then
		t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
		echo "open $ms"; return 0
	fi
	t1=$(date +%s%N); ms=$(( (t1 - t0) / 1000000 ))
	if (( ms < 2500 )); then echo "closed $ms"; else echo "filtered $ms"; fi
}

# path_probe <peer-ip> <tunnel-port>
path_probe() {
	local ip="$1" port="$2" out line rtt st ms p
	P_RTT=0; P_JIT=0; P_LOSS=0; P_MTU=0; P_ICMP=0; P_HOPS=0
	P_TCP_STATE="unknown"; P_TCP_MS=0; P_PORT_STATE="unknown"; P_UDP_STATE="unknown"
	log_info "Probing the route to ${ip} (20 pings, MTU discovery, TCP/UDP reachability)..."
	out=$(ping -n -c 20 -i 0.2 -W 2 "$ip" 2>/dev/null)
	if [[ -n "$out" ]]; then
		p=$(grep -oE '[0-9]+(\.[0-9]+)?% packet loss' <<< "$out" | grep -oE '^[0-9]+(\.[0-9]+)?' | head -n1)
		[[ -n "$p" ]] && P_LOSS=$(ap_int "$p")
		line=$(grep -E 'min/avg/max' <<< "$out" | tail -n1)
		if [[ -n "$line" ]]; then
			rtt="${line##*= }"; rtt="${rtt% ms}"
			P_RTT=$(ap_int "$(cut -d/ -f2 <<< "$rtt")")
			P_JIT=$(ap_int "$(cut -d/ -f4 <<< "$rtt")")
			P_ICMP=1
		fi
	fi
	read -r st ms <<< "$(tcp_probe "$ip" "$port")"
	P_PORT_STATE="$st"
	for p in 22 80 443; do
		read -r st ms <<< "$(tcp_probe "$ip" "$p")"
		if [[ "$st" == "open" ]]; then
			P_TCP_STATE="reachable (tcp/${p})"; P_TCP_MS="$ms"; break
		elif [[ "$st" == "closed" ]]; then
			P_TCP_STATE="reachable (rst on tcp/${p})"; P_TCP_MS="$ms"; break
		fi
		P_TCP_STATE="filtered"
	done
	if (( P_ICMP == 0 )); then
		ap_note "ICMP is filtered on this route, so RTT comes from the TCP handshake and the MTU cannot be probed."
		[[ "$P_TCP_MS" =~ ^[0-9]+$ ]] && (( P_TCP_MS > 0 )) && { P_RTT=$P_TCP_MS; P_LOSS=0; }
	fi
	P_MTU=$(mtu_probe "$ip")
	if have dig; then
		if timeout 4 dig +time=2 +tries=1 +short @1.1.1.1 example.com >/dev/null 2>&1; then P_UDP_STATE="egress OK (udp/53)"; else P_UDP_STATE="blocked/filtered"; fi
	elif have nslookup; then
		if timeout 4 nslookup example.com 1.1.1.1 >/dev/null 2>&1; then P_UDP_STATE="egress OK (udp/53)"; else P_UDP_STATE="blocked/filtered"; fi
	fi
	if have tracepath; then
		P_HOPS=$(timeout 25 tracepath -n -m 20 "$ip" 2>/dev/null | grep -cE '^[[:space:]]*[0-9]+:')
	elif have traceroute; then
		P_HOPS=$(timeout 25 traceroute -n -w 1 -q 1 -m 20 "$ip" 2>/dev/null | grep -cE '^[[:space:]]*[0-9]+')
	fi
	[[ "$P_HOPS" =~ ^[0-9]+$ ]] || P_HOPS=0
	(( P_LOSS >= 15 )) && ap_note "Packet loss is ${P_LOSS}%: this route is unstable, a second exit or provider is worth testing."
	(( P_JIT >= 40 )) && ap_note "Jitter is ${P_JIT} ms: the path is congested, aggressive profiles would make it worse."
	[[ "$P_PORT_STATE" == "open" ]] && ap_note "TCP/${port} already has a real listener on the peer: pick another tunnel port, a raw tunnel must not share it."
	[[ "$P_TCP_STATE" == "filtered" ]] && ap_note "No TCP answer at all from ${ip}: check the provider firewall before blaming the tunnel."
	return 0
}

#--- 3. bandwidth --------------------------------------------------------------
ap_iperf_mbps() {
	awk '/receiver/ { for (i = 1; i <= NF; i++) if ($i ~ /bits\/sec/) { v = $(i - 1) + 0; u = $i; if (u ~ /^G/) v = v * 1000; else if (u ~ /^K/) v = v / 1000; printf "%d\n", v + 0.5 } }' | tail -n1
}

ap_curl_down() {
	local urls=("https://speed.cloudflare.com/__down?bytes=50000000" "https://proof.ovh.net/files/100Mb.dat" "http://speedtest.tele2.net/100MB.zip") u sp best=0
	for u in "${urls[@]}"; do
		sp=$(curl -fsS -o /dev/null --max-time 15 -w '%{speed_download}' "$u" 2>/dev/null)
		sp=$(ap_int "${sp:-0}")
		(( sp > best )) && best=$sp
		(( best > 0 )) && break
	done
	echo $(( best * 8 / 1000000 ))
}

ap_curl_up() {
	local sp
	sp=$(head -c 20000000 /dev/zero 2>/dev/null | curl -fsS -o /dev/null --max-time 15 -w '%{speed_upload}' -X POST --data-binary @- "https://speed.cloudflare.com/__up" 2>/dev/null)
	sp=$(ap_int "${sp:-0}")
	echo $(( sp * 8 / 1000000 ))
}

bw_probe() {
	local ip="${1:-}" how down up
	how=$(ap_choose "How should the line speed be measured?" "internet" \
		"iperf3|iperf3|most accurate: needs 'iperf3 -s' running on the other server" \
		"internet|internet test|download + upload against public speed servers" \
		"manual|I know it|type the values your provider promises" \
		"skip|skip|use the NIC link speed / safe defaults")
	case "$how" in
		iperf3)
			if have iperf3 && [[ -n "$ip" ]]; then
				log_info "iperf3 download test against ${ip}..."
				down=$(timeout 40 iperf3 -c "$ip" -t 6 -P 4 -R 2>/dev/null | ap_iperf_mbps)
				log_info "iperf3 upload test against ${ip}..."
				up=$(timeout 40 iperf3 -c "$ip" -t 6 -P 4 2>/dev/null | ap_iperf_mbps)
				BW_DOWN=$(ap_int "${down:-0}"); BW_UP=$(ap_int "${up:-0}"); BW_SRC="iperf3 to ${ip}"
			else
				log_warn "iperf3 is not installed here, or no peer IP was given."
			fi
			;;
		internet)
			log_info "Measuring the download speed (about 15 s)..."
			BW_DOWN=$(ap_int "$(ap_curl_down)")
			log_info "Measuring the upload speed (about 15 s)..."
			BW_UP=$(ap_int "$(ap_curl_up)")
			BW_SRC="internet speed test"
			(( BW_DOWN == 0 )) && log_warn "The speed test failed (no internet or blocked), please enter the values."
			;;
	esac
	if (( BW_DOWN <= 0 )); then
		BW_DOWN=$(ap_int "$(ap_choose "Download speed of THIS server (Mbit/s)" "100" \
			"10|10 Mbit|ADSL or weak mobile" \
			"25|25 Mbit|VDSL" \
			"50|50 Mbit|good VDSL / FTTH" \
			"100|100 Mbit|FTTH or datacenter, typical" \
			"200|200 Mbit|fast datacenter" \
			"500|500 Mbit|premium datacenter" \
			"1000|1000 Mbit|1 Gbit uplink")")
		BW_SRC="entered by hand"
	fi
	if (( BW_UP <= 0 )); then
		BW_UP=$(ap_int "$(ap_choose "Upload speed of THIS server (Mbit/s)" "$BW_DOWN" \
			"5|5 Mbit|typical Iranian ADSL upload" \
			"10|10 Mbit|VDSL upload" \
			"50|50 Mbit|FTTH upload" \
			"100|100 Mbit|symmetric 100 Mbit" \
			"200|200 Mbit|fast datacenter" \
			"500|500 Mbit|premium datacenter" \
			"1000|1000 Mbit|1 Gbit uplink" \
			"${BW_DOWN}|same as download|symmetric line")")
	fi
	if (( HW_NIC_SPEED > 0 && BW_DOWN > HW_NIC_SPEED )); then
		ap_note "The NIC link is only ${HW_NIC_SPEED} Mbit, so ${BW_DOWN} Mbit cannot be reached: capped."
		BW_DOWN=$HW_NIC_SPEED
	fi
	(( BW_UP > 0 && BW_DOWN > BW_UP * 5 )) && ap_note "Upload (${BW_UP}) is far below download (${BW_DOWN}): ACKs travel upstream, so the window is sized from the upload."
	return 0
}

#--- 4. the planner ------------------------------------------------------------
plan_config() {
	local eff bdp safety w need cap mtu rtt
	PLAN_PURPOSE=$(ap_choose "What matters most on this tunnel?" "balanced" \
		"balanced|balanced|good speed with a sane ping - best for mixed use (web, video, apps)" \
		"download|throughput|maximum download/upload, the ping may rise a little" \
		"latency|low ping|gaming, VoIP, SSH, trading - speed is secondary")
	case "$PLAN_PURPOSE" in
		latency)  PLAN_PROFILE="iran-game" ;;
		download) if (( P_LOSS >= 3 )); then PLAN_PROFILE="iran"; else PLAN_PROFILE="iran-max"; fi ;;
		*)        PLAN_PROFILE="iran" ;;
	esac
	if [[ "$PLAN_PROFILE" == "iran-game" ]] && (( P_LOSS >= 5 )); then
		PLAN_PROFILE="iran"
		ap_note "Loss is ${P_LOSS}%: the no-congestion profile would flood the path, so the balanced profile is used."
	fi
	if [[ "$PLAN_PROFILE" == "iran-max" ]] && (( P_JIT >= 40 )); then
		PLAN_PROFILE="iran"
		ap_note "Jitter is ${P_JIT} ms: the aggressive profile is replaced by the balanced one."
	fi
	if (( P_MTU >= 1280 )); then
		mtu=$(( P_MTU - 100 ))
	elif (( P_MTU > 0 )); then
		mtu=$(( P_MTU - 60 ))
		ap_note "Path MTU is only ${P_MTU} bytes (PPPoE or another tunnel in the path)."
	else
		mtu=1400
		ap_note "Path MTU could not be probed, so the safe value 1400 is used."
	fi
	(( P_LOSS >= 3 )) && mtu=$(( mtu - 50 ))
	(( mtu > 1400 )) && mtu=1400
	(( mtu < 1200 )) && mtu=1200
	PLAN_MTU=$(( mtu / 10 * 10 ))
	eff=$BW_DOWN
	(( BW_UP > 0 && BW_UP * 8 < eff )) && eff=$(( BW_UP * 8 ))
	(( eff <= 0 )) && eff=100
	if   (( eff >= 600 && HW_CORES >= 8 )); then PLAN_CONN=16
	elif (( eff >= 300 && HW_CORES >= 4 )); then PLAN_CONN=8
	elif (( eff >= 100 && HW_CORES >= 2 )); then PLAN_CONN=4
	else PLAN_CONN=2
	fi
	[[ "$PLAN_PURPOSE" == "latency" ]] && PLAN_CONN=2
	if (( P_LOSS >= 5 && PLAN_CONN > 2 )); then
		PLAN_CONN=2
		ap_note "With ${P_LOSS}% loss fewer streams retransmit less, so conn is limited to 2."
	fi
	(( HW_CORES <= 1 )) && PLAN_CONN=2
	(( PLAN_CONN > HW_CORES * 4 )) && PLAN_CONN=$(( HW_CORES * 4 ))
	rtt=$P_RTT
	if (( rtt <= 0 )); then rtt=60; ap_note "RTT was not measured, 60 ms is assumed for the window calculation."; fi
	bdp=$(( eff * 125 * rtt ))
	safety=200
	[[ "$PLAN_PURPOSE" == "download" ]] && safety=250
	[[ "$PLAN_PURPOSE" == "latency" ]] && safety=100
	(( P_LOSS >= 3 )) && safety=$(( safety - 80 ))
	(( safety < 100 )) && safety=100
	w=$(( bdp * safety / 100 / PLAN_MTU / PLAN_CONN ))
	(( w < 128 )) && w=128
	if (( HW_MEM > 0 )); then
		cap=$(( HW_MEM * 1024 * 1024 / 4 ))
		while (( w > 128 )); do
			need=$(( w * PLAN_MTU * PLAN_CONN * 2 ))
			(( need <= cap )) && break
			w=$(( w / 2 ))
			[[ " ${PLAN_NOTES[*]} " == *"limited by RAM"* ]] || ap_note "The window is limited by RAM (${HW_MEM} MB) so the tunnel cannot trigger an OOM kill."
		done
	fi
	if   (( w <= 192 ));   then PLAN_WND=128
	elif (( w <= 320 ));   then PLAN_WND=256
	elif (( w <= 768 ));   then PLAN_WND=512
	elif (( w <= 1536 ));  then PLAN_WND=1024
	elif (( w <= 3072 ));  then PLAN_WND=2048
	elif (( w <= 6144 ));  then PLAN_WND=4096
	elif (( w <= 12288 )); then PLAN_WND=8192
	elif (( w <= 24576 )); then PLAN_WND=16384
	else PLAN_WND=32768
	fi
	if [[ "$PLAN_PURPOSE" == "latency" ]] && (( PLAN_WND > 1024 )); then
		PLAN_WND=1024
		ap_note "For low ping the window stays small on purpose: a huge window means bufferbloat."
	fi
	if (( HW_AES == 1 )); then
		PLAN_BLOCK="aes"
	else
		PLAN_BLOCK="salsa20"
		ap_note "This CPU has no AES-NI, so salsa20 is used - much faster in software."
	fi
	return 0
}

ap_report() {
	local i
	echo
	echo -e "${BOLD}${BLUE}=============== AUTO-PILOT REPORT ===============${NC}"
	echo -e "${BOLD}Server${NC}"
	printf "  %-14s %s\n" "CPU" "${HW_CPU} (${HW_CORES} core/s)"
	printf "  %-14s %s\n" "AES-NI" "$(ap_yn "$HW_AES")"
	printf "  %-14s %s\n" "RAM" "${HW_MEM} MB"
	printf "  %-14s %s\n" "Virtualization" "${HW_VIRT}"
	printf "  %-14s %s\n" "Kernel" "${HW_KERNEL}"
	printf "  %-14s %s\n" "NIC" "${AP_IFACE} / ${HW_NIC_DRV} / link ${HW_NIC_SPEED} Mbit / qdisc ${HW_QDISC}"
	printf "  %-14s %s\n" "BBR + CAKE" "$(ap_yn "$HW_BBR") + $(ap_yn "$HW_CAKE")"
	echo -e "${BOLD}Route to the peer${NC}"
	printf "  %-14s %s\n" "RTT / jitter" "${P_RTT} ms / ${P_JIT} ms"
	printf "  %-14s %s\n" "Packet loss" "${P_LOSS} %"
	printf "  %-14s %s\n" "Path MTU" "${P_MTU}"
	printf "  %-14s %s\n" "Tunnel port" "${P_PORT_STATE} (closed or filtered is the healthy answer)"
	printf "  %-14s %s\n" "TCP" "${P_TCP_STATE}"
	printf "  %-14s %s\n" "UDP egress" "${P_UDP_STATE}"
	printf "  %-14s %s\n" "Hops" "${P_HOPS}"
	echo -e "${BOLD}Bandwidth${NC}"
	printf "  %-14s %s\n" "Down / Up" "${BW_DOWN} / ${BW_UP} Mbit  (${BW_SRC})"
	echo -e "${BOLD}Transport chosen for you${NC}"
	printf "  %-14s %s\n" "Goal" "${PLAN_PURPOSE}"
	printf "  %-14s %s\n" "Profile" "${PLAN_PROFILE}"
	printf "  %-14s %s\n" "MTU" "${PLAN_MTU}"
	printf "  %-14s %s\n" "conn" "${PLAN_CONN}"
	printf "  %-14s %s\n" "window" "${PLAN_WND}"
	printf "  %-14s %s\n" "cipher" "${PLAN_BLOCK}"
	printf "  %-14s %s\n" "protocol" "${PLAN_PROTO}"
	if (( ${#PLAN_NOTES[@]} )); then
		echo -e "${BOLD}${YELLOW}What I noticed${NC}"
		for i in "${!PLAN_NOTES[@]}"; do echo "  $(( i + 1 )). ${PLAN_NOTES[$i]}"; done
	fi
	echo -e "${BOLD}${BLUE}=================================================${NC}"
}

#--- 5. deep Linux / NIC optimization -----------------------------------------
DEEP_SYSCTL="/etc/sysctl.d/99-paqqet-deep.conf"
NIC_SCRIPT="/usr/local/bin/paqqet-nic.sh"
NIC_ENV="/etc/paqet/nic.env"
NIC_SERVICE="/etc/systemd/system/paqqet-nic.service"
PAQET_DROPIN="/etc/systemd/system/paqet@.service.d"

deep_optimize() {
	local mbps="${1:-0}" iface="${2:-}" mem=67108864 cc=""
	need_root
	[[ "$mbps" =~ ^[0-9]+$ ]] || mbps=0
	(( HW_CORES <= 1 )) && hw_probe
	[[ -n "$iface" ]] || iface="${AP_IFACE:-${DETECTED_IFACE:-}}"
	[[ -n "$iface" ]] || iface=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
	if (( mbps == 0 )); then
		mbps=$(ap_int "$(ap_choose "Line speed of this server (used to shape the queue)" "100" \
			"0|unknown|no shaping, only fq_codel" \
			"50|50 Mbit|" \
			"100|100 Mbit|" \
			"200|200 Mbit|" \
			"500|500 Mbit|" \
			"1000|1 Gbit|")")
	fi
	(( mbps >= 500 )) && mem=134217728
	(( HW_BBR == 1 )) && cc="net.ipv4.tcp_congestion_control = bbr"
	log_info "Writing the kernel tuning to ${DEEP_SYSCTL}..."
	mkdir -p "$(dirname "$DEEP_SYSCTL")" 2>/dev/null || true
	cat > "$DEEP_SYSCTL" << SYSEOF
# paQQet deep tuning - generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# sized for ~${mbps} Mbit, ${HW_CORES} core/s, ${HW_MEM} MB RAM
net.core.rmem_max = ${mem}
net.core.wmem_max = ${mem}
net.core.rmem_default = 1048576
net.core.wmem_default = 1048576
net.core.optmem_max = 262144
net.core.netdev_max_backlog = 65536
net.core.netdev_budget = 600
net.core.netdev_budget_usecs = 8000
net.core.somaxconn = 65535
net.core.default_qdisc = fq
${cc}
net.ipv4.tcp_rmem = 4096 262144 ${mem}
net.ipv4.tcp_wmem = 4096 262144 ${mem}
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_notsent_lowat = 131072
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_retries2 = 8
net.ipv4.ip_local_port_range = 10240 65000
net.ipv4.ip_forward = 1
fs.file-max = 2097152
fs.nr_open = 2097152
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5
SYSEOF
	sysctl --system >/dev/null 2>&1 || sysctl -p "$DEEP_SYSCTL" >/dev/null 2>&1 || true
	mkdir -p /etc/modules-load.d 2>/dev/null || true
	printf 'tcp_bbr\nnf_conntrack\nsch_cake\n' > /etc/modules-load.d/99-paqqet-deep.conf 2>/dev/null || true
	log_info "Writing the NIC tuning script to ${NIC_SCRIPT}..."
	mkdir -p "$(dirname "$NIC_SCRIPT")" 2>/dev/null || true
	cat > "$NIC_SCRIPT" << 'NICEOF'
#!/usr/bin/env bash
# paQQet NIC tuning - executed at boot by paqqet-nic.service
[[ -f /etc/paqet/nic.env ]] && . /etc/paqet/nic.env
IF="${PAQQET_NIC_IFACE:-}"
MBPS="${PAQQET_NIC_MBPS:-0}"
CAKE="${PAQQET_NIC_CAKE:-0}"
[[ -n "$IF" ]] || IF=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
[[ -n "$IF" && -d "/sys/class/net/${IF}" ]] || exit 0

# paqet reads raw frames with pcap: coalescing hides packets, so GRO/LRO must be off
ethtool -K "$IF" gro off lro off 2>/dev/null

# biggest ring buffers the NIC offers -> fewer drops during bursts
RX=$(ethtool -g "$IF" 2>/dev/null | awk '/^Pre-set maximums:/, /^Current/ { if ($1 == "RX:") { print $2; exit } }')
TX=$(ethtool -g "$IF" 2>/dev/null | awk '/^Pre-set maximums:/, /^Current/ { if ($1 == "TX:") { print $2; exit } }')
[[ "$RX" =~ ^[0-9]+$ ]] && ethtool -G "$IF" rx "$RX" 2>/dev/null
[[ "$TX" =~ ^[0-9]+$ ]] && ethtool -G "$IF" tx "$TX" 2>/dev/null
ethtool -C "$IF" adaptive-rx on 2>/dev/null
ip link set dev "$IF" txqueuelen 10000 2>/dev/null

# queue discipline: shaped cake kills bufferbloat, fq_codel is the fallback
Q=""
if [[ "$CAKE" == "1" && "$MBPS" =~ ^[0-9]+$ ]] && (( MBPS > 0 )); then
	tc qdisc replace dev "$IF" root cake bandwidth $(( MBPS * 95 / 100 ))mbit besteffort ack-filter 2>/dev/null && Q=cake
fi
if [[ -z "$Q" ]]; then
	tc qdisc replace dev "$IF" root fq_codel 2>/dev/null && Q=fq_codel
fi
[[ -z "$Q" ]] && tc qdisc replace dev "$IF" root fq 2>/dev/null

# spread packet processing over all cores (RPS/XPS) - matters a lot on a 1-2 core VPS
CORES=$(nproc 2>/dev/null || echo 1)
MASK=$(printf '%x' $(( (1 << CORES) - 1 )))
for q in /sys/class/net/${IF}/queues/rx-*; do
	[[ -w "${q}/rps_cpus" ]] && echo "$MASK" > "${q}/rps_cpus" 2>/dev/null
	[[ -w "${q}/rps_flow_cnt" ]] && echo 4096 > "${q}/rps_flow_cnt" 2>/dev/null
done
for q in /sys/class/net/${IF}/queues/tx-*; do
	[[ -w "${q}/xps_cpus" ]] && echo "$MASK" > "${q}/xps_cpus" 2>/dev/null
done
[[ -w /proc/sys/net/core/rps_sock_flow_entries ]] && echo 32768 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null

# no CPU frequency scaling in the middle of a transfer
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
	[[ -w "$g" ]] && echo performance > "$g" 2>/dev/null
done
exit 0
NICEOF
	chmod +x "$NIC_SCRIPT"
	mkdir -p "$(dirname "$NIC_ENV")" 2>/dev/null || true
	cat > "$NIC_ENV" << ENVEOF
PAQQET_NIC_IFACE="${iface}"
PAQQET_NIC_MBPS="${mbps}"
PAQQET_NIC_CAKE="${HW_CAKE}"
ENVEOF
	cat > "$NIC_SERVICE" << UNITEOF
[Unit]
Description=paQQet NIC and queue tuning
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=-${NIC_ENV}
ExecStart=${NIC_SCRIPT}

[Install]
WantedBy=multi-user.target
UNITEOF
	mkdir -p "$PAQET_DROPIN" 2>/dev/null || true
	cat > "${PAQET_DROPIN}/10-paqqet-perf.conf" << DROPEOF
[Service]
Nice=-10
IOSchedulingClass=best-effort
IOSchedulingPriority=0
LimitNOFILE=1048576
LimitMEMLOCK=infinity
DROPEOF
	systemctl daemon-reload >/dev/null 2>&1 || true
	systemctl enable --now paqqet-nic.service >/dev/null 2>&1 || bash "$NIC_SCRIPT" >/dev/null 2>&1 || true
	log_ok "Deep optimization applied (sysctl + NIC + qdisc + RPS/XPS + service limits) and it survives reboot."
	return 0
}

# apply_transport <inst> <profile> <mtu> <wnd> <conn> [cipher] [--no-restart]
apply_transport() {
	local inst="$1" prof="$2" mtu="$3" wnd="$4" conn="$5" cipher="${6:-}" norestart="${7:-}"
	local cfg="${CONFIG_DIR}/${inst}.yaml" m="${META_DIR}/${inst}.meta" key tmp k
	[[ -f "$cfg" ]] || { log_err "Config not found: ${cfg}"; return 1; }
	valid_profile "$prof" || { log_err "Unknown profile: ${prof}"; return 1; }
	valid_mtu "$mtu"     || { log_err "Bad MTU: ${mtu}"; return 1; }
	valid_wnd "$wnd"     || { log_err "Bad window: ${wnd}"; return 1; }
	valid_conn "$conn"   || { log_err "Bad conn: ${conn}"; return 1; }
	key=$(grep -m1 -E '^[[:space:]]*key:' "$cfg" | sed -E 's/^[^"]*"//; s/".*$//')
	[[ -n "$key" ]] || { log_err "Cannot read the key from ${cfg}."; return 1; }
	[[ -n "$cipher" ]] && SEL_BLOCK="$cipher"
	tmp=$(mktemp) || return 1
	awk '/^[ \t]*kcp:[ \t]*$/ { exit } { print }' "$cfg" > "$tmp"
	sed -i -E "s/^([ \t]*conn:).*/\1 ${conn}/" "$tmp"
	kcp_block "$key" "$mtu" "$prof" "$wnd" >> "$tmp"
	if ! validate_yaml "$tmp"; then
		rm -f "$tmp"; log_err "The generated config did not validate, nothing was changed."; return 1
	fi
	cat "$tmp" > "$cfg"; rm -f "$tmp"; chmod 600 "$cfg" 2>/dev/null || true
	if [[ -f "$m" ]]; then
		sed -i -E "s/^MTU=.*/MTU=${mtu}/; s/^PROFILE=.*/PROFILE=${prof}/; s/^WND=.*/WND=${wnd}/; s/^CONN=.*/CONN=${conn}/; s/^BLOCK=.*/BLOCK=${SEL_BLOCK}/" "$m"
		for k in "MTU=${mtu}" "PROFILE=${prof}" "WND=${wnd}" "CONN=${conn}" "BLOCK=${SEL_BLOCK}"; do
			grep -q "^${k%%=*}=" "$m" || echo "$k" >> "$m"
		done
	fi
	if [[ "$norestart" != "--no-restart" ]]; then
		systemctl restart "paqet@${inst}" >/dev/null 2>&1 || true
		sleep 2
		if systemctl is-active --quiet "paqet@${inst}"; then
			log_ok "Instance ${inst}: profile=${prof} mtu=${mtu} conn=${conn} window=${wnd} cipher=${SEL_BLOCK}"
		else
			log_warn "Instance ${inst} did not come back up - check: journalctl -u paqet@${inst} -n 40"
		fi
	fi
	return 0
}

#--- 6. what the other server needs -------------------------------------------
AP_SELF_URL="${PAQQET_SELF_URL:-https://raw.githubusercontent.com/xSOH3ILx/paQQet/main/paQQet.sh}"

# peer_recipe <this-role> <inst> <ip> <port> <key> <mtu> <prof> <wnd> <conn> <cipher> <proto> <ports> [peer-name]
peer_recipe() {
	local role="$1" inst="$2" ip="$3" port="$4" key="$5" mtu="$6" prof="$7" wnd="$8" conn="$9"
	local cipher="${10}" proto="${11}" ports="${12}" peer_name="${13:-}"
	local f="${BACKUP_DIR}/paqqet-peer-${inst}.txt" cmd there
	mkdir -p "$BACKUP_DIR" 2>/dev/null || true
	if [[ "$role" == "client" ]]; then
		[[ -n "$peer_name" ]] || peer_name="ir"
		there="EXIT node (server side, abroad)"
		cmd="PAQQET_BLOCK=${cipher} paQQet server --name ${peer_name} --port ${port} --key ${key} --mtu ${mtu} --profile ${prof} --conn ${conn} --wnd ${wnd} --block ${cipher} --yes"
	else
		[[ -n "$peer_name" ]] || peer_name="$inst"
		there="IRAN hub (client side)"
		cmd="PAQQET_BLOCK=${cipher} paQQet client --name ${peer_name} --remote ${ip} --port ${port} --key ${key} --ports \"${ports:-2053}\" --proto ${proto} --mtu ${mtu} --profile ${prof} --conn ${conn} --wnd ${wnd} --yes"
	fi
	{
		echo "paQQet ${SCRIPT_VERSION} - settings for the OTHER server (instance '${inst}')"
		echo "generated $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo
		printf '  %-12s: %s\n' "that side" "$there"
		printf '  %-12s: %s\n' "peer IP" "$ip"
		printf '  %-12s: %s\n' "port" "$port"
		printf '  %-12s: %s\n' "key" "$key"
		printf '  %-12s: %s\n' "MTU" "$mtu"
		printf '  %-12s: %s\n' "profile" "$prof"
		printf '  %-12s: %s\n' "conn" "$conn"
		printf '  %-12s: %s\n' "window" "$wnd"
		printf '  %-12s: %s\n' "cipher" "$cipher"
		printf '  %-12s: %s\n' "protocol" "$proto"
		[[ -n "$ports" ]] && printf '  %-12s: %s\n' "ports" "$ports"
		echo
		echo "1) install paQQet + the core there:"
		echo "     bash <(curl -fsSL ${AP_SELF_URL}) install"
		echo "2) create the matching side (one line, copy it as it is):"
		echo "     ${cmd}"
		if [[ "$role" == "server" ]]; then
			echo
			echo "   --ports takes localport>remoteport pairs, e.g. 2053 or 8080>443 or 9000>10.0.0.5:9000"
			echo "   (change it to the ports your panel really uses on the Iran hub)"
		fi
		echo
		echo "IMPORTANT: key, MTU, profile, conn, window and cipher must be IDENTICAL on both sides,"
		echo "otherwise the tunnel comes up but no traffic passes."
	} > "$f"
	chmod 600 "$f" 2>/dev/null || true
	echo
	echo -e "${BOLD}${GREEN}=========== COPY THIS TO THE OTHER SERVER ===========${NC}"
	cat "$f"
	echo -e "${BOLD}${GREEN}=====================================================${NC}"
	log_ok "Saved as paqqet-peer-${inst}.txt in ${BACKUP_DIR} (${f})"
	return 0
}

#--- 7. the auto-pilot ---------------------------------------------------------
autopilot() {
	local role ip inst port key ports proto myip np speed
	need_root
	[[ -x "$BIN_PATH" ]] || die "Install the paqet core first (menu option 1 / paQQet install)."
	P_RTT=0; P_JIT=0; P_LOSS=0; P_MTU=0; P_ICMP=0; P_HOPS=0
	P_TCP_STATE="unknown"; P_TCP_MS=0; P_PORT_STATE="unknown"; P_UDP_STATE="unknown"
	BW_DOWN=0; BW_UP=0; BW_SRC="not measured"; PLAN_NOTES=()
	echo
	echo -e "${BOLD}${MAGENTA}AUTO-PILOT${NC} - I test this server and the route, then build the best tunnel."
	detect_network_details
	log_info "Step 1/5: reading hardware, kernel and NIC..."
	hw_probe
	role=$(ap_choose "Which side is THIS server?" "client" \
		"client|Iran hub|users connect here, traffic leaves through the server abroad" \
		"server|exit node|the server abroad that provides the internet")
	if [[ "$role" == "client" ]]; then
		ip=$(ask "Public IP of the EXIT server (abroad): " "")
		valid_ipv4 "$ip" || die "Invalid IPv4 address: ${ip}"
	else
		ip=$(ask "Public IP of the IRAN hub (optional, only used to test the route): " "")
		if [[ -n "$ip" ]]; then valid_ipv4 "$ip" || die "Invalid IPv4 address: ${ip}"; fi
	fi
	inst=$(ask "Instance name (letters/digits, e.g. de1) [tun1]: " "tun1")
	valid_name "$inst" || die "Invalid instance name: ${inst}"
	port=$(ask "Tunnel port [${DEF_EXIT_PORT}]: " "$DEF_EXIT_PORT")
	valid_port "$port" || die "Invalid port: ${port}"
	case "$port" in
		22|53|80|443|8080|8443) ap_note "Port ${port} is a well known service port: DPI watches it and a real service may need it." ;;
	esac
	if [[ "$role" == "server" ]] && port_in_use "$port" tcp; then
		np=$(free_port_from 9500) || np=""
		if [[ -n "$np" ]]; then
			log_warn "A real service already listens on ${port}; using ${np} instead."
			port="$np"
		fi
	fi
	key=$(ask "Shared key (Enter = generate a new one): " "")
	if [[ -z "$key" ]]; then
		key=$(gen_key)
		log_info "A new key was generated; the other server must use exactly the same key."
	fi
	if [[ "$role" == "client" ]]; then
		ports=$(ask "Local ports to forward (e.g. 2053 or 8080>443, comma separated) [2053]: " "2053")
		proto=$(ap_choose "Which protocol should be forwarded?" "tcp" \
			"tcp|tcp|panels, web, Xray TCP/WS/gRPC inbounds" \
			"udp|udp|WireGuard, QUIC/Hysteria, DNS, game traffic" \
			"both|both|TCP and UDP on the same ports")
	else
		ports=""; proto="tcp"
	fi
	PLAN_PROTO="$proto"
	if [[ -n "$ip" ]]; then
		log_info "Step 2/5: probing the route to ${ip}..."
		path_probe "$ip" "$port"
	else
		log_warn "Step 2/5 skipped: without the peer IP the route cannot be measured, safe defaults are used."
	fi
	log_info "Step 3/5: line speed..."
	bw_probe "$ip"
	log_info "Step 4/5: computing the best transport..."
	plan_config
	ap_report
	confirm "Build the tunnel with these settings now?" "y" || { log_warn "Cancelled, nothing was changed."; return 1; }
	SEL_BLOCK="$PLAN_BLOCK"
	log_info "Step 5/5: writing the configuration and starting the service..."
	if [[ "$role" == "server" ]]; then
		configure_server "$inst" "$port" "$key" "$PLAN_MTU" "$PLAN_PROFILE" "$PLAN_CONN" "$PLAN_WND"
	else
		reset_client_vars
		C_NAME="$inst"; C_REMOTE="$ip"; C_PORT="$port"; C_KEY="$key"
		C_PORTS="$ports"; C_PROTO="$proto"
		C_MTU="$PLAN_MTU"; C_PROF="$PLAN_PROFILE"; C_CONN="$PLAN_CONN"; C_WND="$PLAN_WND"
		configure_client
	fi
	if confirm "Apply the deep Linux/NIC optimization on this server too (recommended)?" "y"; then
		speed=$BW_DOWN
		(( BW_UP > speed )) && speed=$BW_UP
		deep_optimize "$speed" "$AP_IFACE"
	fi
	myip="${PUBLIC_IP:-}"
	valid_ipv4 "$myip" || myip="${DETECTED_IP:-}"
	if [[ "$role" == "server" ]]; then
		peer_recipe server "$inst" "$myip" "$port" "$key" "$PLAN_MTU" "$PLAN_PROFILE" "$PLAN_WND" "$PLAN_CONN" "$PLAN_BLOCK" "$proto" "$ports"
	else
		peer_recipe client "$inst" "$ip" "$port" "$key" "$PLAN_MTU" "$PLAN_PROFILE" "$PLAN_WND" "$PLAN_CONN" "$PLAN_BLOCK" "$proto" "$ports"
	fi
	log_info "When both sides are up, menu option 21 benchmarks the profiles and keeps the fastest one."
	return 0
}

#--- 8. live benchmark ---------------------------------------------------------
BENCH_IP=""

# bench_measure <iperf3|socks|latency> <port> -> "<mbps> <rtt-ms>"
bench_measure() {
	local mode="$1" port="$2" mbps=0 rtt=0 out
	case "$mode" in
		iperf3)
			if have iperf3 && [[ -n "$BENCH_IP" ]]; then
				mbps=$(timeout 30 iperf3 -c "$BENCH_IP" -p "$port" -t 5 -P 4 -R 2>/dev/null | ap_iperf_mbps)
			fi
			;;
		socks)
			out=$(curl -fsS -o /dev/null --max-time 25 --socks5-hostname "127.0.0.1:${port}" -w '%{speed_download}' "https://speed.cloudflare.com/__down?bytes=30000000" 2>/dev/null)
			mbps=$(( $(ap_int "${out:-0}") * 8 / 1000000 ))
			;;
	esac
	mbps=$(ap_int "${mbps:-0}")
	if [[ -n "$BENCH_IP" ]]; then
		out=$(ping -n -c 10 -i 0.2 -W 2 "$BENCH_IP" 2>/dev/null | grep -E 'min/avg/max' | tail -n1)
		if [[ -n "$out" ]]; then
			out="${out##*= }"; out="${out% ms}"
			rtt=$(ap_int "$(cut -d/ -f2 <<< "$out")")
		fi
	fi
	echo "${mbps} ${rtt}"
}

benchmark_tunnel() {
	local inst="${1:-}" mode port depth cur_key cur_mtu cur_conn cur_block
	local prof wnd mbps rtt score best_score=-999999 best_prof="" best_wnd="" line
	local -a profiles=() results=()
	need_root
	if [[ -z "$inst" ]]; then
		inst=$(pick_instance) || return 1
	fi
	[[ -f "${CONFIG_DIR}/${inst}.yaml" ]] || { log_err "Instance ${inst} does not exist."; return 1; }
	BENCH_IP=$(meta_get "$inst" REMOTE_IP)
	cur_key=$(meta_get "$inst" KEY)
	cur_mtu=$(meta_get "$inst" MTU); [[ -n "$cur_mtu" ]] || cur_mtu="$DEF_MTU"
	cur_conn=$(meta_get "$inst" CONN); [[ -n "$cur_conn" ]] || cur_conn="$DEF_CONN"
	cur_block=$(meta_get "$inst" BLOCK); [[ -n "$cur_block" ]] || cur_block="$DEF_BLOCK"
	echo
	echo -e "${BOLD}${MAGENTA}BENCHMARK${NC} - each profile is applied for a few seconds and measured, the winner stays."
	log_warn "The tunnel restarts several times during the test, so users will see short drops."
	mode=$(ap_choose "How should the speed be measured?" "socks" \
		"iperf3|iperf3|needs 'iperf3 -s' on the other server - most accurate" \
		"socks|through the tunnel|downloads through the local SOCKS5 port (client side)" \
		"latency|ping only|no download, only RTT - for gaming/VoIP tuning")
	case "$mode" in
		iperf3) port=$(ask "iperf3 port on the other server [5201]: " "5201") ;;
		socks)  port=$(ask "Local SOCKS5 port of this instance [1080]: " "1080") ;;
		*)      port=0 ;;
	esac
	depth=$(ap_choose "How thorough should the test be?" "quick" \
		"quick|quick|3 profiles, about 1 minute" \
		"full|full|3 profiles x 2 window sizes, about 3 minutes")
	profiles=(iran iran-max iran-game)
	confirm "Start the benchmark on instance ${inst} now?" "y" || return 1
	for prof in "${profiles[@]}"; do
		for wnd in $(profile_sug_wnd "$prof") $( [[ "$depth" == "full" ]] && echo $(( $(profile_sug_wnd "$prof") * 2 )) ); do
			(( wnd > 32768 )) && continue
			log_info "Testing profile=${prof} window=${wnd} ..."
			apply_transport "$inst" "$prof" "$cur_mtu" "$wnd" "$cur_conn" "$cur_block" >/dev/null 2>&1
			sleep 3
			read -r mbps rtt <<< "$(bench_measure "$mode" "$port")"
			if [[ "$mode" == "latency" ]]; then
				score=$(( 0 - rtt * 10 ))
			else
				score=$(( mbps * 10 - rtt * 2 ))
			fi
			results+=("$(printf '%-10s wnd=%-6s %6s Mbit  %5s ms  score=%s' "$prof" "$wnd" "$mbps" "$rtt" "$score")")
			log_info "  -> ${mbps} Mbit, ${rtt} ms (score ${score})"
			if (( score > best_score )); then
				best_score=$score; best_prof="$prof"; best_wnd="$wnd"
			fi
		done
	done
	echo
	echo -e "${BOLD}${BLUE}=============== BENCHMARK RESULT ===============${NC}"
	for line in "${results[@]}"; do echo "  $line"; done
	if [[ -z "$best_prof" ]]; then
		log_err "No measurement succeeded - is the tunnel really up and the port correct?"
		return 1
	fi
	echo -e "${BOLD}${GREEN}  Winner: profile ${best_prof} with window ${best_wnd} (score ${best_score})${NC}"
	echo -e "${BOLD}${BLUE}================================================${NC}"
	apply_transport "$inst" "$best_prof" "$cur_mtu" "$best_wnd" "$cur_conn" "$cur_block"
	{
		echo "paQQet ${SCRIPT_VERSION} benchmark - instance ${inst} - $(date -u +%Y-%m-%dT%H:%M:%SZ)"
		echo "mode=${mode} port=${port} mtu=${cur_mtu} conn=${cur_conn} cipher=${cur_block}"
		for line in "${results[@]}"; do echo "  $line"; done
		echo "winner: profile=${best_prof} window=${best_wnd} score=${best_score}"
	} > "${BACKUP_DIR}/paqqet-bench-${inst}.txt"
	log_ok "Report saved: ${BACKUP_DIR}/paqqet-bench-${inst}.txt"
	log_warn "Apply the same profile and window on the other server, otherwise the tunnel stops passing traffic:"
	peer_recipe "$(meta_get "$inst" ROLE)" "$inst" "${BENCH_IP:-${PUBLIC_IP:-0.0.0.0}}" "$(meta_get "$inst" PORT)" "$cur_key" "$cur_mtu" "$best_prof" "$best_wnd" "$cur_conn" "$cur_block" "$(meta_get "$inst" PROTO)" "$(meta_get "$inst" LOCAL_PORTS)"
	return 0
}

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
  19) Re-tune an instance: profile / MTU / window / cipher
  20) AUTO-PILOT: test the route + this server, then build the best tunnel
  21) Benchmark the profiles on a live tunnel and keep the winner
  22) Deep Linux/NIC optimization (sysctl, qdisc, RPS/XPS, buffers)
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
				pick_profile "$DEF_PROFILE" >/dev/null; pr="$PICKED_PROFILE"
				pick_cipher "${SEL_BLOCK:-$DEF_BLOCK}" >/dev/null
				m=$(pick_mtu "$DEF_MTU")
				PICK_MTU="$m"
				cn=$(pick_conn "${SUG_CONN:-$DEF_CONN}")
				PICK_CONN="$cn"
				wd=$(pick_wnd "${SUG_WND:-$DEF_WND}")
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
			19) retune_instance ;;
			20) autopilot ;;
			21) benchmark_tunnel ;;
			22) deep_optimize ;;
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
    --name N --port P [--key K] [--mtu 1350] [--profile iran] [--block aes] [--conn 4] [--wnd 2048]
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
  retune [name]                  Re-tune profile / MTU / window / cipher in place
  auto           Auto-pilot: probe, plan, build and print the peer command
  bench [name]   Benchmark the profiles on a live tunnel
  deep-optimize  Deep Linux/NIC optimization
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
			--block) SEL_BLOCK="$2"; shift 2 ;;
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
		retune)         retune_instance "${1:-}" ;;
		auto|autopilot) autopilot ;;
		bench|benchmark) benchmark_tunnel "${1:-}" ;;
		deep-optimize)  deep_optimize "${1:-0}" ;;
		uninstall)      uninstall_all ;;
		key)            show_instance_key "${1:-}" ;;
		version|-v|--version) echo "paQQet ${SCRIPT_VERSION}" ;;
		help|-h|--help) usage ;;
		"")             ensure_deps; menu ;;
		*)              log_err "Unknown command: $cmd"; usage; exit 1 ;;
	esac
}

main "$@"
