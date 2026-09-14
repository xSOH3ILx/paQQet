#!/usr/bin/env bash
#===============================================================================
# paQQet v2.1 - Multi-Tunnel Architecture & 3X-UI Integration
# Clean English Terminal UI (To prevent RTL font corruption in SSH/PuTTY)
# Supports: Iran Hub <-> Multi-Exit Nodes (RO, NL, HK, etc.)
#===============================================================================
set -o pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m'

BIN_PATH="/usr/local/bin/paqet"
CONFIG_DIR="/etc/paqet"
BACKUP_DIR="/etc/paqet/backups"
SYSCTL_CONF="/etc/sysctl.d/99-paqet.conf"
SERVICE_TEMPLATE="/etc/systemd/system/paqet@.service"

log_info() { echo -e "${CYAN}[INFO]${NC} $1" >&2; }
log_ok()   { echo -e "${GREEN}[OK]${NC} $1" >&2; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1" >&2; }
log_err()  { echo -e "${RED}[ERROR]${NC} $1" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_err "This script must be run as root."
        exit 1
    fi
}

pause_prompt() {
    local msg="${1:-Press [Enter] or any key to return to main menu...}"
    echo -e "\n${YELLOW}${msg}${NC}"
    read -r -n 1 -s dummy 2>/dev/null || read -r dummy 2>/dev/null || true
}

detect_and_cleanup_legacy() {
    local auto_yes="${1:-false}"
    log_info "Scanning for legacy or third-party Paqet installations..."
    
    local legacy_services=()
    while IFS= read -r svc; do
        if [[ -n "$svc" ]]; then
            legacy_services+=("$svc")
        fi
    done < <(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}' | grep -E '^(paqet-server|paqet-client|paqet|paqet-x-.*|paqctl-.*|gfk-.*)\.service' || true)

    local found_legacy=false
    if [[ ${#legacy_services[@]} -gt 0 ]]; then
        found_legacy=true
    fi

    # Check other locations
    local old_bins=()
    for b in "/usr/local/bin/Paqet-X" "/usr/bin/Paqet-X" "/usr/bin/paqet" "/opt/paqet/paqet" "/usr/local/bin/paqctl"; do
        if [[ -f "$b" ]]; then
            old_bins+=("$b")
            found_legacy=true
        fi
    done

    if [[ "$found_legacy" = true ]]; then
        echo -e "${YELLOW}------------------------------------------------------------${NC}"
        echo -e "${YELLOW}[!] Legacy or existing Paqet installations detected:${NC}"
        for s in "${legacy_services[@]}"; do
            echo -e "  • Service: ${RED}$s${NC}"
        done
        for b in "${old_bins[@]}"; do
            echo -e "  • Binary:  ${RED}$b${NC}"
        done
        echo -e "${YELLOW}------------------------------------------------------------${NC}"

        local confirm="y"
        if [[ "$auto_yes" != "true" ]]; then
            read -rp "Do you want to clean up legacy installations before proceeding? [Y/n]: " confirm
            confirm=${confirm:-y}
        fi

        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            log_info "Stopping and removing legacy services..."
            for s in "${legacy_services[@]}"; do
                systemctl stop "$s" 2>/dev/null || true
                systemctl disable "$s" 2>/dev/null || true
                rm -f "/etc/systemd/system/$s" "/usr/lib/systemd/system/$s" 2>/dev/null || true
                log_ok "Removed legacy service: $s"
            done

            for b in "${old_bins[@]}"; do
                rm -f "$b" 2>/dev/null || true
                log_ok "Removed legacy binary: $b"
            done

            # Clean crontab entries related to old paqet
            crontab -l 2>/dev/null | grep -vE 'paqet|paqctl' | crontab - 2>/dev/null || true

            systemctl daemon-reload
            log_ok "Legacy cleanup completed successfully."
        else
            log_warn "Skipped legacy cleanup as requested."
        fi
    else
        log_ok "No conflicting legacy installations found."
    fi
}

install_dependencies() {
    log_info "Checking and installing required system packages..."
    local deps=("curl" "tar" "iproute2" "iptables" "ethtool" "libpcap0.8" "sqlite3" "python3" "openssl")
    local missing=()
    for d in "${deps[@]}"; do
        if ! command -v "$d" >/dev/null 2>&1 && ! dpkg -s "$d" >/dev/null 2>&1; then
            missing+=("$d")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing packages: ${missing[*]}"
        apt-get update -qq && apt-get install -y -qq "${missing[@]}" libpcap-dev || true
    fi
    log_ok "Dependencies are up-to-date."
}

get_latest_paqet_version() {
    local ver=""
    # 1. Query GitHub API
    ver=$(curl -sL --max-time 5 "https://api.github.com/repos/hanselime/paqet/releases/latest" 2>/dev/null | grep -Po '"tag_name":\s*"\K[^"]*' | tr -d '[:space:]' || true)
    # 2. Scrape redirect if rate-limited
    if [[ -z "$ver" ]]; then
        ver=$(curl -sIL -o /dev/null -w "%{url_effective}" --max-time 6 "https://github.com/hanselime/paqet/releases/latest" 2>/dev/null | grep -Po 'releases/tag/\K.*' | tr -d '[:space:]' || true)
    fi
    # 3. Fallback to pinned stable release
    if [[ -z "$ver" ]]; then
        ver="v1.0.0-alpha.21"
        log_warn "GitHub unreachable or rate-limited; fallback to stable: $ver"
    else
        log_ok "Latest Paqet release identified: $ver"
    fi
    echo "$ver"
}

download_paqet() {
    local target_ver="$1"
    local arch
    arch=$(uname -m)
    local paqet_arch=""

    case "$arch" in
        x86_64) paqet_arch="amd64" ;;
        aarch64|arm64) paqet_arch="arm64" ;;
        armv7l) paqet_arch="arm32" ;;
        *) log_err "Unsupported CPU architecture: $arch"; return 1 ;;
    esac

    local tar_name="paqet-linux-${paqet_arch}-${target_ver}.tar.gz"
    local dl_url="https://github.com/hanselime/paqet/releases/download/${target_ver}/${tar_name}"

    log_info "Downloading Paqet (${target_ver}) for linux-${paqet_arch}..."
    local tmp_dir
    tmp_dir=$(mktemp -d)

    if ! curl -fsSL --retry 3 --max-time 45 "$dl_url" -o "${tmp_dir}/${tar_name}"; then
        local fallback_url="https://github.com/hanselime/paqet/releases/latest/download/${tar_name}"
        log_warn "Primary URL failed. Trying fallback: $fallback_url"
        if ! curl -fsSL --retry 2 --max-time 45 "$fallback_url" -o "${tmp_dir}/${tar_name}"; then
            log_err "Failed to download Paqet archive from $dl_url"
            rm -rf "$tmp_dir"
            return 1
        fi
    fi

    tar -xzf "${tmp_dir}/${tar_name}" -C "$tmp_dir" 2>/dev/null || {
        log_err "Failed to extract tar archive."
        rm -rf "$tmp_dir"
        return 1
    }

    local bin_file
    bin_file=$(find "$tmp_dir" -type f -name "paqet*" ! -name "*.tar.gz" ! -name "*.yaml*" ! -name "*.md" 2>/dev/null | head -n1)

    if [[ -z "$bin_file" || ! -f "$bin_file" ]]; then
        log_err "Paqet binary not found inside extracted archive."
        rm -rf "$tmp_dir"
        return 1
    fi

    chmod +x "$bin_file"
    mv "$bin_file" "$BIN_PATH"
    rm -rf "$tmp_dir"
    log_ok "Paqet binary successfully installed to $BIN_PATH ($($BIN_PATH version 2>/dev/null || echo "$target_ver"))"
    return 0
}

detect_hardware_specs() {
    local cores
    cores=$(nproc 2>/dev/null || echo 2)
    local mem_kb
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local mem_mb=$(( mem_kb / 1024 ))

    log_info "Hardware detected: $cores CPU core(s) | $mem_mb MB RAM"

    # Dynamic resource-aware tuning
    if (( mem_mb < 2048 )); then
        TUNED_CONN=3
        TUNED_SNDWND=1024
        TUNED_RCVWND=1024
        TUNED_SOCKBUF=4194304
        TUNED_SMUXBUF=2097152
        TUNED_STREAMBUF=1048576
        TUNED_PCAP_SOCKBUF=4194304
    elif (( mem_mb < 6144 )); then
        TUNED_CONN=4
        TUNED_SNDWND=2048
        TUNED_RCVWND=2048
        TUNED_SOCKBUF=8388608
        TUNED_SMUXBUF=4194304
        TUNED_STREAMBUF=2097152
        TUNED_PCAP_SOCKBUF=8388608
    else
        TUNED_CONN=6
        TUNED_SNDWND=4096
        TUNED_RCVWND=4096
        TUNED_SOCKBUF=16777216
        TUNED_SMUXBUF=8388608
        TUNED_STREAMBUF=4194304
        TUNED_PCAP_SOCKBUF=16777216
    fi
}

detect_network_details() {
    local target_ip="${1:-1.1.1.1}"
    
    ROUTE_INFO=$(ip route get "$target_ip" 2>/dev/null || ip route show default | head -n1)
    DETECTED_IFACE=$(echo "$ROUTE_INFO" | grep -Po 'dev \K[^\s]+' | head -n1)
    DETECTED_IP=$(echo "$ROUTE_INFO" | grep -Po 'src \K[^\s]+' | head -n1)

    if [[ -z "$DETECTED_IFACE" ]]; then
        DETECTED_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1)
    fi
    if [[ -z "$DETECTED_IP" ]]; then
        DETECTED_IP=$(ip -4 addr show dev "$DETECTED_IFACE" | grep -Po '(?<=inet )[\d.]+' | head -n1)
    fi

    # Detect Gateway MAC
    DETECTED_GW=$(ip route show default | grep -Po '(?<=via )[\d.]+' | head -n1 || true)
    DETECTED_MAC=""
    if [[ -n "$DETECTED_GW" ]]; then
        DETECTED_MAC=$(ip neigh show "$DETECTED_GW" dev "$DETECTED_IFACE" | grep -Po '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1 || true)
        if [[ -z "$DETECTED_MAC" ]]; then
            ping -c 2 -W 1 "$DETECTED_GW" >/dev/null 2>&1 || true
            DETECTED_MAC=$(ip neigh show "$DETECTED_GW" dev "$DETECTED_IFACE" | grep -Po '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n1 || true)
        fi
    fi

    if [[ -z "$DETECTED_MAC" ]]; then
        DETECTED_MAC="ff:ff:ff:ff:ff:ff"
        log_warn "Gateway MAC not found; using broadcast: $DETECTED_MAC"
    else
        log_ok "Network: Dev=$DETECTED_IFACE | IP=$DETECTED_IP | RouterMAC=$DETECTED_MAC"
    fi
}

apply_sysctl_optimizations() {
    log_info "Applying high-performance kernel tuning ($SYSCTL_CONF)..."
    cat > "$SYSCTL_CONF" << 'EOF'
# Paqet High Performance Kernel Tuning
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 65535
net.core.optmem_max = 25165824

net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1

net.netfilter.nf_conntrack_max = 2097152
net.netfilter.nf_conntrack_tcp_timeout_established = 86400

net.ipv4.ip_forward = 1
net.ipv4.ip_local_port_range = 1024 65535
fs.file-max = 2097152
EOF

    if modprobe tcp_bbr >/dev/null 2>&1 && lsmod | grep -q bbr; then
        echo "net.core.default_qdisc = fq" >> "$SYSCTL_CONF"
        echo "net.ipv4.tcp_congestion_control = bbr" >> "$SYSCTL_CONF"
    fi

    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true
    log_ok "Kernel parameters successfully optimized."
}

apply_nic_queue_tuning() {
    local iface="$1"
    if [[ -n "$iface" ]] && ip link show "$iface" >/dev/null 2>&1; then
        ip link set dev "$iface" txqueuelen 10000 2>/dev/null || true
        if command -v ethtool >/dev/null 2>&1; then
            ethtool -G "$iface" rx 4096 tx 4096 >/dev/null 2>&1 || true
        fi
        log_ok "NIC queue optimized ($iface txqueuelen=10000)."
    fi
}

generate_random_key() {
    openssl rand -hex 16 2>/dev/null || od -vN 16 -An -tx1 /dev/urandom | tr -d ' \n'
}

install_systemd_template() {
    cat > "$SERVICE_TEMPLATE" << 'EOF'
[Unit]
Description=Paqet Tunnel Instance (%i)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
LimitNOFILE=1048576
LimitNPROC=512000
ExecStart=/usr/local/bin/paqet run -c /etc/paqet/%i.yaml
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_ok "Systemd template service installed: paqet@.service"
}

setup_iptables_server() {
    local port="$1"
    iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK
    iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK
    iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || \
        iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
}

setup_iptables_client() {
    local port="$1"
    iptables -t raw -C OUTPUT -p tcp --dport "$port" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A OUTPUT -p tcp --dport "$port" -j NOTRACK
    iptables -t raw -C PREROUTING -p tcp --sport "$port" -j NOTRACK 2>/dev/null || \
        iptables -t raw -A PREROUTING -p tcp --sport "$port" -j NOTRACK
    iptables -t mangle -C OUTPUT -p tcp --dport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || \
        iptables -t mangle -A OUTPUT -p tcp --dport "$port" --tcp-flags RST RST -j DROP
}

configure_server() {
    local name="${1:-server}"
    local port="${2:-8443}"
    local key="${3:-$(generate_random_key)}"
    local mtu="${4:-1280}"

    detect_and_cleanup_legacy false
    detect_network_details "8.8.8.8"
    detect_hardware_specs
    apply_sysctl_optimizations
    apply_nic_queue_tuning "$DETECTED_IFACE"

    mkdir -p "$CONFIG_DIR"
    local cfg_file="$CONFIG_DIR/${name}.yaml"

    cat > "$cfg_file" << EOF
role: "server"

log:
  level: "info"

listen:
  addr: ":${port}"

network:
  interface: "${DETECTED_IFACE}"
  ipv4:
    addr: "${DETECTED_IP}:${port}"
    router_mac: "${DETECTED_MAC}"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]
  pcap:
    sockbuf: ${TUNED_PCAP_SOCKBUF}

transport:
  protocol: "kcp"
  conn: ${TUNED_CONN}
  kcp:
    mode: "fast"
    key: "${key}"
    mtu: ${mtu}
    sndwnd: ${TUNED_SNDWND}
    rcvwnd: ${TUNED_RCVWND}
    nodelay: 1
    interval: 20
    resend: 1
    nocongestion: 1
    sockbuf: ${TUNED_SOCKBUF}
    smuxbuf: ${TUNED_SMUXBUF}
    streambuf: ${TUNED_STREAMBUF}
EOF

    setup_iptables_server "$port"
    install_systemd_template

    systemctl enable --now "paqet@${name}"
    log_ok "Paqet Server instance [paqet@${name}] is now ACTIVE."
    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}       CLIENT CONNECTION PARAMETERS (FOR IRAN SERVER)       ${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "  • Remote IP   : ${CYAN}${DETECTED_IP}${NC}"
    echo -e "  • Remote Port : ${CYAN}${port}${NC}"
    echo -e "  • Secret Key  : ${YELLOW}${key}${NC}"
    echo -e "  • MTU         : ${CYAN}${mtu}${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

configure_client() {
    local node_name="$1"
    local remote_ip="$2"
    local remote_port="$3"
    local secret_key="$4"
    local local_port="$5"
    local target_dest="${6:-127.0.0.1:443}"
    local mtu="${7:-1280}"

    if [[ -z "$node_name" || -z "$remote_ip" || -z "$remote_port" || -z "$secret_key" || -z "$local_port" ]]; then
        log_err "Missing arguments for client configuration."
        echo "Usage: configure_client <node_name> <remote_ip> <remote_port> <secret_key> <local_port> [target_dest] [mtu]"
        return 1
    fi

    detect_network_details "$remote_ip"
    detect_hardware_specs
    apply_sysctl_optimizations
    apply_nic_queue_tuning "$DETECTED_IFACE"

    mkdir -p "$CONFIG_DIR"
    local cfg_file="$CONFIG_DIR/client-${node_name}.yaml"

    cat > "$cfg_file" << EOF
role: "client"

log:
  level: "info"

forward:
  - listen: "0.0.0.0:${local_port}"
    target: "${target_dest}"

network:
  interface: "${DETECTED_IFACE}"
  ipv4:
    addr: "${DETECTED_IP}:0"
    router_mac: "${DETECTED_MAC}"
  tcp:
    local_flag: ["PA"]
    remote_flag: ["PA"]
  pcap:
    sockbuf: ${TUNED_PCAP_SOCKBUF}

server:
  addr: "${remote_ip}:${remote_port}"

transport:
  protocol: "kcp"
  conn: ${TUNED_CONN}
  kcp:
    mode: "fast"
    key: "${secret_key}"
    mtu: ${mtu}
    sndwnd: ${TUNED_SNDWND}
    rcvwnd: ${TUNED_RCVWND}
    nodelay: 1
    interval: 20
    resend: 1
    nocongestion: 1
    sockbuf: ${TUNED_SOCKBUF}
    smuxbuf: ${TUNED_SMUXBUF}
    streambuf: ${TUNED_STREAMBUF}
EOF

    setup_iptables_client "$remote_port"
    install_systemd_template

    systemctl enable --now "paqet@client-${node_name}"
    log_ok "Client tunnel to [${node_name}] is ACTIVE on local port ${local_port} (service: paqet@client-${node_name})."
}

integrate_3x_ui() {
    local tag_name="$1"
    local local_port="$2"

    python3 - << PYEOF
import sqlite3
import json
import os
import shutil
import time

db_paths = ["/etc/x-ui/x-ui.db", "/usr/local/x-ui/db/x-ui.db"]
db_path = None
for p in db_paths:
    if os.path.isfile(p):
        db_path = p
        break

if not db_path:
    print("\033[1;33m[WARN]\033[0m 3X-UI database not found. Skipping panel integration.")
    exit(0)

print(f"\033[0;36m[INFO]\033[0m Detected 3X-UI database: {db_path}")
backup_path = f"{db_path}.bak_{int(time.time())}"
shutil.copy2(db_path, backup_path)
print(f"\033[0;32m[OK]\033[0m Database backup created: {backup_path}")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

cursor.execute("SELECT value FROM settings WHERE key = 'xrayTemplateConfig'")
row = cursor.fetchone()

if not row or not row[0]:
    print("\033[0;31m[ERROR]\033[0m xrayTemplateConfig key not found in settings table.")
    conn.close()
    exit(1)

try:
    template = json.loads(row[0])
except Exception as e:
    print(f"\033[0;31m[ERROR]\033[0m Failed to parse Xray JSON template: {e}")
    conn.close()
    exit(1)

outbounds = template.get("outbounds", [])
tag = "paqet-${tag_name}"
port = int("${local_port}")

new_outbound = {
    "tag": tag,
    "protocol": "socks",
    "settings": {
        "servers": [
            {
                "address": "127.0.0.1",
                "port": port
            }
        ]
    }
}

found_idx = -1
for i, ob in enumerate(outbounds):
    if ob.get("tag") == tag:
        found_idx = i
        break

if found_idx >= 0:
    outbounds[found_idx] = new_outbound
    print(f"\033[0;32m[OK]\033[0m Existing outbound [{tag}] updated.")
else:
    insert_pos = len(outbounds)
    for i, ob in enumerate(outbounds):
        if ob.get("tag") in ["direct", "block"]:
            insert_pos = i
            break
    outbounds.insert(insert_pos, new_outbound)
    print(f"\033[0;32m[OK]\033[0m New outbound [{tag}] inserted safely into Xray template.")

template["outbounds"] = outbounds
updated_json = json.dumps(template, indent=2)

cursor.execute("UPDATE settings SET value = ? WHERE key = 'xrayTemplateConfig'", (updated_json,))
conn.commit()
conn.close()

print("\033[0;32m[OK]\033[0m 3X-UI configuration safely saved without touching other inbounds/users.")
PYEOF

    if systemctl is-active --quiet x-ui; then
        systemctl restart x-ui || true
        log_ok "x-ui service reloaded to apply new template."
    fi
}

list_active_tunnels() {
    echo -e "\n${CYAN}${BOLD}=== ACTIVE PAQET TUNNEL INSTANCES ===${NC}"
    local units
    units=$(systemctl list-units "paqet@*" --no-legend 2>/dev/null | awk '{print $1}' || true)
    if [[ -z "$units" ]]; then
        echo "No active Paqet instances found."
    else
        for u in $units; do
            local st
            st=$(systemctl is-active "$u" 2>/dev/null || echo "inactive")
            if [[ "$st" == "active" ]]; then
                echo -e "  [${GREEN}ACTIVE${NC}] $u"
            else
                echo -e "  [${RED}${st}${NC}] $u"
            fi
        done
    fi
    echo ""
}

remove_tunnel_instance() {
    local instance_name="$1"
    if [[ -z "$instance_name" ]]; then
        read -rp "Enter instance name to remove (e.g., client-romania or server): " instance_name
    fi

    local svc="paqet@${instance_name}.service"
    local cfg="$CONFIG_DIR/${instance_name}.yaml"

    log_info "Stopping and disabling service $svc..."
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
    rm -f "$cfg" 2>/dev/null || true
    log_ok "Instance [${instance_name}] removed."
}

interactive_menu() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "${GREEN}${BOLD}           paQQet - MULTI-TUNNEL ARCHITECTURE TOOL             ${NC}"
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "  ${BOLD}1)${NC} Install / Update Paqet Core (Latest Version + Auto Clean)"
        echo -e "  ${BOLD}2)${NC} Setup Server Node (Kharej / Exit Server)"
        echo -e "  ${BOLD}3)${NC} Add Client Node Tunnel (Iran Server -> Kharej Node)"
        echo -e "  ${BOLD}4)${NC} Integrate Tunnel Outbound into 3X-UI Panel"
        echo -e "  ${BOLD}5)${NC} List All Active Tunnels & Status"
        echo -e "  ${BOLD}6)${NC} Remove / Delete a Tunnel Instance"
        echo -e "  ${BOLD}7)${NC} Clean Legacy / Third-party Paqet Installations"
        echo -e "  ${BOLD}0)${NC} Exit"
        echo -e "${CYAN}----------------------------------------------------------------${NC}"
        if ! read -rp "Select an option [0-7]: " opt; then
            echo ""
            log_info "Session ended or no TTY detected. Exiting menu."
            break
        fi

        case "$opt" in
            1)
                check_root
                detect_and_cleanup_legacy false
                install_dependencies
                latest_v=$(get_latest_paqet_version)
                download_paqet "$latest_v"
                pause_prompt
                ;;
            2)
                check_root
                echo -e "\n${BOLD}--- Setup Kharej Server ---${NC}"
                read -rp "Instance Name [server]: " s_name
                s_name=${s_name:-server}
                read -rp "Server Listen Port [8443]: " s_port
                s_port=${s_port:-8443}
                read -rp "Secret Key (Leave blank to generate random): " s_key
                s_key=${s_key:-$(generate_random_key)}
                read -rp "Tunnel MTU [1280]: " s_mtu
                s_mtu=${s_mtu:-1280}
                configure_server "$s_name" "$s_port" "$s_key" "$s_mtu"
                pause_prompt
                ;;
            3)
                check_root
                echo -e "\n${BOLD}--- Add Kharej Node Tunnel (Iran Hub) ---${NC}"
                read -rp "Node Tag/Name (e.g., romania, netherlands, hk): " c_name
                read -rp "Remote Server IP: " c_ip
                read -rp "Remote Server Port [8443]: " c_port
                c_port=${c_port:-8443}
                read -rp "Secret Key: " c_key
                read -rp "Local Port on Iran Hub for this Node [e.g., 10801]: " c_lport
                read -rp "Target Destination on Kharej [127.0.0.1:443]: " c_dest
                c_dest=${c_dest:-127.0.0.1:443}
                read -rp "MTU [1280]: " c_mtu
                c_mtu=${c_mtu:-1280}
                configure_client "$c_name" "$c_ip" "$c_port" "$c_key" "$c_lport" "$c_dest" "$c_mtu"

                read -rp "Do you want to integrate this outbound into 3X-UI? [y/N]: " add_3x
                if [[ "$add_3x" =~ ^[Yy]$ ]]; then
                    integrate_3x_ui "$c_name" "$c_lport"
                fi
                pause_prompt
                ;;
            4)
                check_root
                echo -e "\n${BOLD}--- 3X-UI Outbound Integration ---${NC}"
                read -rp "Node Tag (e.g., romania): " t_name
                read -rp "Local Port (e.g., 10801): " t_port
                integrate_3x_ui "$t_name" "$t_port"
                pause_prompt
                ;;
            5)
                list_active_tunnels
                pause_prompt
                ;;
            6)
                check_root
                remove_tunnel_instance ""
                pause_prompt
                ;;
            7)
                check_root
                detect_and_cleanup_legacy false
                pause_prompt
                ;;
            0)
                exit 0
                ;;
            *)
                log_err "Invalid selection."
                sleep 1
                ;;
        esac
    done
}

# Entry point: CLI execution or Interactive Menu
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ $# -eq 0 ]]; then
        interactive_menu
    else
        case "$1" in
            install)
                check_root
                detect_and_cleanup_legacy "${2:-false}"
                install_dependencies
                ver=$(get_latest_paqet_version)
                download_paqet "$ver"
                ;;
            server)
                check_root
                configure_server "$2" "$3" "$4" "$5"
                ;;
            client)
                check_root
                configure_client "$2" "$3" "$4" "$5" "$6" "$7" "$8"
                ;;
            integrate-3xui)
                check_root
                integrate_3x_ui "$2" "$3"
                ;;
            list)
                list_active_tunnels
                ;;
            remove)
                check_root
                remove_tunnel_instance "$2"
                ;;
            clean)
                check_root
                detect_and_cleanup_legacy true
                ;;
            *)
                echo "paQQet CLI Usage:"
                echo "  $0                                        (Interactive Menu)"
                echo "  $0 install                                (Clean legacy & install latest)"
                echo "  $0 server <name> <port> <key> [mtu]        (Setup exit server)"
                echo "  $0 client <node> <ip> <port> <key> <lport> [target] [mtu]"
                echo "  $0 integrate-3xui <node> <lport>          (Non-destructive 3X-UI hook)"
                echo "  $0 list                                   (List running tunnels)"
                echo "  $0 remove <instance_name>                 (Remove tunnel)"
                echo "  $0 clean                                  (Force clean legacy installations)"
                exit 1
                ;;
        esac
    fi
fi
