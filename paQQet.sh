#!/usr/bin/env bash
#===============================================================================
# paQQet v3.1 - High-Performance Multi-Tunnel Architecture & Linux Optimizer
# Supports: Iran Multi-Exit Hub <-> Exit Servers (Romania, HK, NL, etc.)
# Clean Terminal UI (English prompts to avoid RTL corruption in SSH terminals)
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
SYSCTL_CONF="/etc/sysctl.d/99-paqqet.conf"
SERVICE_TEMPLATE="/etc/systemd/system/paqet@.service"
WATCHDOG_SCRIPT="/usr/local/bin/paqqet-watchdog.sh"
WATCHDOG_SERVICE="/etc/systemd/system/paqqet-watchdog.service"
WATCHDOG_TIMER="/etc/systemd/system/paqqet-watchdog.timer"

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

#-------------------------------------------------------------------------------
# Deep Scanner & Cleanup for Legacy and Existing Installations
#-------------------------------------------------------------------------------
detect_and_cleanup_legacy() {
    local auto_yes="${1:-false}"
    log_info "Performing deep scan for legacy or running Paqet instances..."
    
    local found_services=()
    local found_pids=()
    local found_bins=()

    # 1. Detect Systemd services
    while IFS= read -r s; do
        [[ -n "$s" ]] && found_services+=("$s")
    done < <(systemctl list-units "paqet*" --type=service --no-legend 2>/dev/null | awk '{print $1}' || true)

    while IFS= read -r s; do
        [[ -n "$s" ]] && found_services+=("$s")
    done < <(systemctl list-unit-files "paqet*" --type=service --no-legend 2>/dev/null | awk '{print $1}' || true)

    for cf in /etc/systemd/system/paq*.service /etc/systemd/system/gfk*.service; do
        if [[ -f "$cf" ]]; then
            local bname
            bname=$(basename "$cf")
            found_services+=("$bname")
        fi
    done

    if [[ ${#found_services[@]} -gt 0 ]]; then
        found_services=($(printf "%s\n" "${found_services[@]}" | sort -u))
    fi

    # 2. Detect running processes
    while IFS= read -r pid; do
        [[ -n "$pid" ]] && found_pids+=("$pid")
    done < <(pgrep -f '(paqet|paqctl|Paqet-X)' 2>/dev/null || true)

    # 3. Detect binaries
    for b in "/usr/local/bin/paqet" "/usr/bin/paqet" "/opt/paqet/paqet" "/usr/local/bin/paqctl" "/usr/local/bin/Paqet-X" "/usr/bin/Paqet-X"; do
        if [[ -f "$b" ]]; then
            found_bins+=("$b")
        fi
    done

    local has_remnants=false
    if [[ ${#found_services[@]} -gt 0 || ${#found_pids[@]} -gt 0 || ${#found_bins[@]} -gt 0 ]]; then
        has_remnants=true
    fi

    if [[ "$has_remnants" = true ]]; then
        echo -e "${YELLOW}------------------------------------------------------------${NC}"
        echo -e "${YELLOW}[!] Existing Paqet installations detected:${NC}"
        for s in "${found_services[@]}"; do echo -e "  • Service: ${RED}$s${NC}"; done
        for p in "${found_pids[@]}"; do echo -e "  • Process: ${RED}PID $p${NC}"; done
        for b in "${found_bins[@]}"; do echo -e "  • Binary:  ${RED}$b${NC}"; done
        echo -e "${YELLOW}------------------------------------------------------------${NC}"

        local confirm="y"
        if [[ "$auto_yes" != "true" ]]; then
            read -rp "Do you want to stop and remove these instances cleanly? [Y/n]: " confirm
            confirm=${confirm:-y}
        fi

        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            log_info "Stopping and disabling services..."
            for s in "${found_services[@]}"; do
                systemctl stop "$s" 2>/dev/null || true
                systemctl disable "$s" 2>/dev/null || true
                rm -f "/etc/systemd/system/$s" "/usr/lib/systemd/system/$s" 2>/dev/null || true
                rm -f "/etc/systemd/system/multi-user.target.wants/$s" 2>/dev/null || true
            done

            if [[ ${#found_pids[@]} -gt 0 ]]; then
                log_info "Terminating running processes..."
                pkill -9 -f '(paqet|paqctl|Paqet-X)' 2>/dev/null || true
            fi

            for b in "${found_bins[@]}"; do
                rm -f "$b" 2>/dev/null || true
                log_ok "Removed binary: $b"
            done

            systemctl daemon-reload
            log_ok "Legacy cleanup completed successfully."
        fi
    else
        log_ok "No conflicting legacy installations found."
    fi
}

#-------------------------------------------------------------------------------
# Complete System Uninstaller
#-------------------------------------------------------------------------------
uninstall_paqqet_completely() {
    echo -e "\n${RED}${BOLD}=== COMPLETE UNINSTALLATION OF paQQet ===${NC}"
    read -rp "Are you sure you want to completely uninstall paQQet and all tunnels? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Uninstall aborted."
        return
    fi

    # Disable watchdog if active
    systemctl stop paqqet-watchdog.timer paqqet-watchdog.service 2>/dev/null || true
    systemctl disable paqqet-watchdog.timer paqqet-watchdog.service 2>/dev/null || true
    rm -f "$WATCHDOG_SCRIPT" "$WATCHDOG_SERVICE" "$WATCHDOG_TIMER"

    detect_and_cleanup_legacy true

    log_info "Removing configuration files, templates and tuning..."
    rm -rf "$CONFIG_DIR"
    rm -f "$SERVICE_TEMPLATE"
    rm -f "$SYSCTL_CONF"
    rm -f /etc/security/limits.d/99-paqqet.conf
    sysctl --system >/dev/null 2>&1 || true

    log_info "Cleaning up firewall rules..."
    iptables -t raw -F 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true

    systemctl daemon-reload
    log_ok "paQQet and all associated files have been completely uninstalled."
}

#-------------------------------------------------------------------------------
# System Dependencies & Core Downloader
#-------------------------------------------------------------------------------
install_dependencies() {
    log_info "Verifying required packages (curl, tar, iproute2, iptables, libpcap, arping)..."
    local deps=("curl" "tar" "iproute2" "iptables" "ethtool" "libpcap0.8" "iputils-arping" "gzip")
    local missing=()
    for d in "${deps[@]}"; do
        if ! command -v "$d" >/dev/null 2>&1 && ! dpkg -s "$d" >/dev/null 2>&1; then
            missing+=("$d")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing missing dependencies: ${missing[*]}"
        apt-get update -qq && apt-get install -y -qq "${missing[@]}" libpcap-dev || true
    fi
    log_ok "System dependencies are verified."
}

get_latest_paqet_version() {
    local ver=""
    ver=$(curl -sL --max-time 5 "https://api.github.com/repos/hanselime/paqet/releases/latest" 2>/dev/null | grep -Po '"tag_name":\s*"\K[^"]*' | tr -d '[:space:]' || true)
    if [[ -z "$ver" ]]; then
        ver="v1.0.0-alpha.21"
        log_warn "Fallback to verified stable version: $ver"
    else
        log_ok "Latest official Paqet release identified: $ver"
    fi
    echo "$ver"
}

download_paqet() {
    local target_ver="$1"
    local arch
    arch=$(uname -m)
    local paqet_arch=""

    case "$arch" in
        x86_64|amd64) paqet_arch="amd64" ;;
        aarch64|arm64) paqet_arch="arm64" ;;
        *) log_err "Unsupported CPU architecture: $arch"; return 1 ;;
    esac

    local bin_name="paqet_linux_${paqet_arch}"
    local url="https://github.com/hanselime/paqet/releases/download/${target_ver}/${bin_name}"
    local tar_url="https://github.com/hanselime/paqet/releases/download/${target_ver}/paqet-linux-${paqet_arch}-${target_ver}.tar.gz"

    mkdir -p /usr/local/bin "$CONFIG_DIR"
    log_info "Downloading Paqet binary from GitHub..."

    if curl -sL --fail --max-time 30 "$url" -o "$BIN_PATH" 2>/dev/null; then
        chmod +x "$BIN_PATH"
    elif curl -sL --fail --max-time 45 "$tar_url" | tar -zx -O "$bin_name" > "$BIN_PATH" 2>/dev/null; then
        chmod +x "$BIN_PATH"
    else
        log_err "Failed to download Paqet binary. Check network access to GitHub."
        return 1
    fi

    log_ok "Installed executable: $BIN_PATH ($($BIN_PATH version 2>/dev/null || echo "$target_ver"))"
}

#-------------------------------------------------------------------------------
# Network Parameters Discovery
#-------------------------------------------------------------------------------
detect_network_details() {
    local target_ip="${1:-8.8.8.8}"
    local route_info
    route_info=$(ip route get "$target_ip" 2>/dev/null || ip route show default | head -n1)

    DETECTED_IFACE=$(echo "$route_info" | grep -Po '(?<=dev\s)\S+' | head -n1)
    DETECTED_IP=$(echo "$route_info" | grep -Po '(?<=src\s)\S+' | head -n1)

    if [[ -z "$DETECTED_IFACE" ]]; then
        DETECTED_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev\s)\S+' | head -n1)
    fi
    if [[ -z "$DETECTED_IP" && -n "$DETECTED_IFACE" ]]; then
        DETECTED_IP=$(ip -4 addr show dev "$DETECTED_IFACE" | grep -Po '(?<=inet\s)[\d.]+' | head -n1)
    fi

    # Discover Gateway IP
    local gw_ip
    gw_ip=$(echo "$route_info" | grep -Po '(?<=via\s)\S+' | head -n1)
    if [[ -z "$gw_ip" ]]; then
        gw_ip=$(ip route show default | grep -Po '(?<=via\s)\S+' | head -n1)
    fi

    DETECTED_MAC=""
    if [[ -n "$gw_ip" ]]; then
        DETECTED_MAC=$(ip -4 neigh show to "$gw_ip" dev "$DETECTED_IFACE" 2>/dev/null | grep -Po '(?<=lladdr\s)[0-9a-fA-F:]{17}' | head -n1)
        if [[ -z "$DETECTED_MAC" ]]; then
            ping -c 2 -W 1 "$gw_ip" >/dev/null 2>&1 || true
            arping -c 2 -I "$DETECTED_IFACE" "$gw_ip" >/dev/null 2>&1 || true
            DETECTED_MAC=$(ip -4 neigh show to "$gw_ip" dev "$DETECTED_IFACE" 2>/dev/null | grep -Po '(?<=lladdr\s)[0-9a-fA-F:]{17}' | head -n1)
        fi
    fi

    if [[ -z "$DETECTED_MAC" ]]; then
        log_warn "Gateway MAC not found automatically."
        read -rp "Please enter your Gateway Router MAC address: " DETECTED_MAC
    fi

    log_ok "Detected: Interface=$DETECTED_IFACE | Local IP=$DETECTED_IP | Gateway MAC=$DETECTED_MAC"
}

#-------------------------------------------------------------------------------
# Linux Network & Kernel Optimizer (Top-tier Sysctl & NIC Tuning)
#-------------------------------------------------------------------------------
apply_linux_optimizations() {
    log_info "Applying Linux network stack and TCP/BBR optimizations..."
    cat > "$SYSCTL_CONF" << 'EOF'
# paQQet High Performance VPS Tuning
fs.file-max = 2097152
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
EOF

    if modprobe tcp_bbr >/dev/null 2>&1 && lsmod | grep -q bbr; then
        echo "net.core.default_qdisc = fq" >> "$SYSCTL_CONF"
        echo "net.ipv4.tcp_congestion_control = bbr" >> "$SYSCTL_CONF"
        log_ok "TCP BBR Congestion Control activated."
    fi

    sysctl -p "$SYSCTL_CONF" >/dev/null 2>&1 || true

    cat > /etc/security/limits.d/99-paqqet.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
* soft nproc 512000
* hard nproc 512000
root soft nofile 1048576
root hard nofile 1048576
EOF

    if [[ -n "$DETECTED_IFACE" ]] && ip link show "$DETECTED_IFACE" >/dev/null 2>&1; then
        ip link set dev "$DETECTED_IFACE" txqueuelen 10000 2>/dev/null || true
        ethtool -G "$DETECTED_IFACE" rx 4096 tx 4096 2>/dev/null || true
    fi

    log_ok "System network stack fully optimized."
}

#-------------------------------------------------------------------------------
# DNS Management Subsystem
#-------------------------------------------------------------------------------
manage_dns() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "${GREEN}${BOLD}                 paQQet - DNS CONFIGURATION                    ${NC}"
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "Current DNS in /etc/resolv.conf:"
        grep 'nameserver' /etc/resolv.conf | awk '{print "  • "$0}' || echo "  (None)"
        echo -e "----------------------------------------------------------------"
        echo -e "  ${BOLD}1)${NC} Quad9 (9.9.9.9, 149.112.112.112) [Highly Recommended & Anti-Censorship]"
        echo -e "  ${BOLD}2)${NC} Cloudflare (1.1.1.1, 1.0.0.1)"
        echo -e "  ${BOLD}3)${NC} Google (8.8.8.8, 8.8.4.4)"
        echo -e "  ${BOLD}4)${NC} Shecan (178.22.122.100, 185.51.200.2) [Iran Sanction Bypass]"
        echo -e "  ${BOLD}5)${NC} Electro (78.157.42.100, 78.157.42.101) [Iran Sanction Bypass]"
        echo -e "  ${BOLD}6)${NC} Custom DNS Servers"
        echo -e "  ${BOLD}0)${NC} Return to Main Menu"
        echo -e "${CYAN}================================================================${NC}"
        read -rp "Select an option [0-6]: " dns_choice

        local ns1=""
        local ns2=""
        case "$dns_choice" in
            1) ns1="9.9.9.9"; ns2="149.112.112.112" ;;
            2) ns1="1.1.1.1"; ns2="1.0.0.1" ;;
            3) ns1="8.8.8.8"; ns2="8.8.4.4" ;;
            4) ns1="178.22.122.100"; ns2="185.51.200.2" ;;
            5) ns1="78.157.42.100"; ns2="78.157.42.101" ;;
            6)
                read -rp "Enter Primary DNS: " ns1
                read -rp "Enter Secondary DNS: " ns2
                ;;
            0) return ;;
            *) log_err "Invalid option."; sleep 1; continue ;;
        esac

        if [[ -n "$ns1" ]]; then
            chattr -i /etc/resolv.conf 2>/dev/null || true
            cp /etc/resolv.conf /etc/resolv.conf.bak_paqqet 2>/dev/null || true
            cat > /etc/resolv.conf << EOF
nameserver $ns1
$([[ -n "$ns2" ]] && echo "nameserver $ns2")
options timeout:2 attempts:3 rotate
EOF
            log_ok "DNS successfully updated to: $ns1 ${ns2:+(and $ns2)}"
            pause_prompt
        fi
    done
}

#-------------------------------------------------------------------------------
# Systemd Service Template & Firewall Rules
#-------------------------------------------------------------------------------
install_systemd_template() {
    cat > "$SERVICE_TEMPLATE" << 'EOF'
[Unit]
Description=paQQet Raw Tunnel Instance (%i)
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
}

setup_iptables_server() {
    local port="$1"
    iptables -t raw -C PREROUTING -p tcp --dport "$port" -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp --dport "$port" -j NOTRACK
    iptables -t raw -C OUTPUT -p tcp --sport "$port" -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp --sport "$port" -j NOTRACK
    iptables -t mangle -C OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p tcp --dport "$port" -j ACCEPT
}

setup_iptables_client() {
    local port="$1"
    iptables -t raw -C OUTPUT -p tcp --dport "$port" -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp --dport "$port" -j NOTRACK
    iptables -t raw -C PREROUTING -p tcp --sport "$port" -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp --sport "$port" -j NOTRACK
    iptables -t mangle -C OUTPUT -p tcp --tcp-flags RST RST -j DROP 2>/dev/null || iptables -t mangle -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
}

#-------------------------------------------------------------------------------
# Setup Exit Server (Kharej Node)
#-------------------------------------------------------------------------------
configure_server() {
    local name="${1:-server}"
    local port="${2:-8443}"
    local key="${3:-$(openssl rand -hex 16)}"
    local mtu="${4:-1300}"

    detect_network_details "8.8.8.8"
    apply_linux_optimizations

    mkdir -p "$CONFIG_DIR"
    local cfg_file="$CONFIG_DIR/${name}.yaml"

    echo -e "\n${BOLD}Select KCP Tuning Profile for Exit Server:${NC}"
    echo -e "  1) Channel Fast3 [Best for Iran filtering & high packet-loss] (Recommended)"
    echo -e "  2) Developer Normal Bandwidth [mode: manual, nodelay: 0, resend: 0]"
    echo -e "  3) Developer Low Latency / Gaming [mode: manual, nodelay: 1, resend: 2]"
    read -rp "Select profile [1-3, default 1]: " prof_choice
    prof_choice=${prof_choice:-1}

    local kcp_block=""
    case "$prof_choice" in
        2)
            kcp_block=$(cat << EOF
  kcp:
    mode: "manual"
    block: "aes"
    key: "${key}"
    mtu: ${mtu}
    nodelay: 0
    interval: 10
    resend: 0
    nocongestion: 1
    wdelay: true
    acknodelay: false
    rcvwnd: 4096
    sndwnd: 4096
EOF
)
            ;;
        3)
            kcp_block=$(cat << EOF
  kcp:
    mode: "manual"
    block: "aes"
    key: "${key}"
    mtu: ${mtu}
    nodelay: 1
    interval: 10
    resend: 2
    nocongestion: 1
    wdelay: false
    acknodelay: true
    rcvwnd: 4096
    sndwnd: 4096
EOF
)
            ;;
        *)
            kcp_block=$(cat << EOF
  kcp:
    mode: "fast3"
    block: "aes"
    key: "${key}"
    mtu: ${mtu}
    rcvwnd: 2048
    sndwnd: 2048
EOF
)
            ;;
    esac

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
    local_flag: ["PA", "A"]
  pcap:
    sockbuf: 8388608

transport:
  protocol: "kcp"
  conn: 4
${kcp_block}
EOF

    setup_iptables_server "$port"
    install_systemd_template

    systemctl enable --now "paqet@${name}"
    log_ok "Exit server instance [paqet@${name}] is ACTIVE."
    echo ""
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}       CLIENT PARAMETERS (ENTER THESE ON IRAN SERVER)        ${NC}"
    echo -e "${GREEN}${BOLD}════════════════════════════════════════════════════════════${NC}"
    echo -e "  • Remote IP   : ${CYAN}${DETECTED_IP}${NC}"
    echo -e "  • Remote Port : ${CYAN}${port}${NC}"
    echo -e "  • Secret Key  : ${YELLOW}${key}${NC}"
    echo -e "  • MTU         : ${CYAN}${mtu}${NC}"
    echo -e "${GREEN}════════════════════════════════════════════════════════════${NC}"
}

#-------------------------------------------------------------------------------
# Setup Client (Iran Hub Node)
#-------------------------------------------------------------------------------
configure_client() {
    local node_name="$1"
    local remote_ip="$2"
    local remote_port="${3:-8443}"
    local secret_key="$4"
    local local_port="${5:-1080}"
    local target_dest="${6:-127.0.0.1:1080}"
    local mtu="${7:-1300}"

    if [[ -z "$node_name" || -z "$remote_ip" || -z "$remote_port" || -z "$secret_key" || -z "$local_port" ]]; then
        log_err "Missing arguments for client configuration."
        return 1
    fi

    detect_network_details "$remote_ip"
    apply_linux_optimizations

    mkdir -p "$CONFIG_DIR"
    local cfg_file="$CONFIG_DIR/client-${node_name}.yaml"

    echo -e "\n${BOLD}Select Inbound Mode on Iran Server:${NC}"
    echo -e "  1) Port Forwarding (TCP + UDP) [Direct raw mapping to exit server destination] (Recommended)"
    echo -e "  2) SOCKS5 Proxy Mode [Local SOCKS5 proxy on port ${local_port}]"
    read -rp "Select mode [1-2, default 1]: " in_mode
    in_mode=${in_mode:-1}

    local inbound_section=""
    if [[ "$in_mode" == "2" ]]; then
        inbound_section=$(cat << EOF
socks5:
  - listen: "0.0.0.0:${local_port}"
EOF
)
    else
        inbound_section=$(cat << EOF
forward:
  - listen: "0.0.0.0:${local_port}"
    target: "${target_dest}"
    protocol: "tcp"
  - listen: "0.0.0.0:${local_port}"
    target: "${target_dest}"
    protocol: "udp"
EOF
)
    fi

    echo -e "\n${BOLD}Select KCP Tuning Profile (Must match Exit Server profile):${NC}"
    echo -e "  1) Channel Fast3 [Best for Iran filtering & high packet-loss] (Recommended)"
    echo -e "  2) Developer Normal Bandwidth [mode: manual, nodelay: 0, resend: 0]"
    echo -e "  3) Developer Low Latency / Gaming [mode: manual, nodelay: 1, resend: 2]"
    read -rp "Select profile [1-3, default 1]: " prof_choice
    prof_choice=${prof_choice:-1}

    local kcp_block=""
    case "$prof_choice" in
        2)
            kcp_block=$(cat << EOF
  kcp:
    mode: "manual"
    block: "aes"
    key: "${secret_key}"
    mtu: ${mtu}
    nodelay: 0
    interval: 10
    resend: 0
    nocongestion: 1
    wdelay: true
    acknodelay: false
    rcvwnd: 4096
    sndwnd: 4096
EOF
)
            ;;
        3)
            kcp_block=$(cat << EOF
  kcp:
    mode: "manual"
    block: "aes"
    key: "${secret_key}"
    mtu: ${mtu}
    nodelay: 1
    interval: 10
    resend: 2
    nocongestion: 1
    wdelay: false
    acknodelay: true
    rcvwnd: 4096
    sndwnd: 4096
EOF
)
            ;;
        *)
            kcp_block=$(cat << EOF
  kcp:
    mode: "fast3"
    block: "aes"
    key: "${secret_key}"
    mtu: ${mtu}
    rcvwnd: 2048
    sndwnd: 2048
EOF
)
            ;;
    esac

    cat > "$cfg_file" << EOF
role: "client"

log:
  level: "info"

${inbound_section}

network:
  interface: "${DETECTED_IFACE}"
  ipv4:
    addr: "${DETECTED_IP}:0"
    router_mac: "${DETECTED_MAC}"
  tcp:
    local_flag: ["PA", "A"]
    remote_flag: ["PA", "A"]
  pcap:
    sockbuf: 4194304

server:
  addr: "${remote_ip}:${remote_port}"

transport:
  protocol: "kcp"
  conn: 4
${kcp_block}
EOF

    setup_iptables_client "$remote_port"
    install_systemd_template

    systemctl enable --now "paqet@client-${node_name}"
    log_ok "Client tunnel [paqet@client-${node_name}] is ACTIVE on local port ${local_port}."
}

#-------------------------------------------------------------------------------
# Comprehensive Tunnel Connection Diagnostics
#-------------------------------------------------------------------------------
test_tunnel_connectivity() {
    echo -e "\n${CYAN}${BOLD}=== paQQet ACTIVE TUNNEL DIAGNOSTICS ===${NC}"
    local cfgs=("$CONFIG_DIR"/*.yaml)
    if [[ ! -e "${cfgs[0]}" ]]; then
        log_warn "No tunnel configurations found in $CONFIG_DIR."
        return
    fi

    for cfg in "${cfgs[@]}"; do
        local bname
        bname=$(basename "$cfg" .yaml)
        local svc="paqet@${bname}"
        echo -e "\n${MAGENTA}------------------------------------------------------------${NC}"
        echo -e "${BOLD}Instance:${NC} ${CYAN}${bname}${NC} (${svc})"
        
        if systemctl is-active --quiet "$svc"; then
            echo -e "  • Service Status : ${GREEN}ACTIVE (Running)${NC}"
        else
            echo -e "  • Service Status : ${RED}INACTIVE / FAILED${NC}"
        fi

        local role
        role=$(grep -Po '(?<=role:\s*")[^"]+' "$cfg" || true)
        if [[ "$role" == "client" ]]; then
            local s_addr
            s_addr=$(grep -Po '(?<=addr:\s*")[^"]+' "$cfg" | tail -n 1 || true)
            echo -e "  • Remote Server  : ${YELLOW}${s_addr}${NC}"
            echo -n "  • Raw Packet Ping: "
            if "$BIN_PATH" ping -c "$cfg" >/tmp/paqet_ping.log 2>&1; then
                echo -e "${GREEN}SUCCESSFUL${NC}"
            else
                echo -e "${RED}FAILED${NC} (Check log in /tmp/paqet_ping.log)"
            fi
        fi

        echo -e "  • Recent Logs:"
        journalctl -u "$svc" -n 4 --no-pager 2>/dev/null | while read -r line; do
            echo -e "    ${line}"
        done
    done
    echo -e "${MAGENTA}------------------------------------------------------------${NC}"
}

list_active_tunnels() {
    echo -e "\n${CYAN}${BOLD}=== CONFIGURED TUNNEL INSTANCES ===${NC}"
    for cfg in "$CONFIG_DIR"/*.yaml; do
        if [[ -f "$cfg" ]]; then
            local bname
            bname=$(basename "$cfg" .yaml)
            local status
            status=$(systemctl is-active "paqet@$bname" 2>/dev/null || echo "unknown")
            local role
            role=$(grep -Po '(?<=role:\s*")[^"]+' "$cfg" || true)
            echo -e "  • Instance: ${BOLD}${bname}${NC} | Role: ${CYAN}${role}${NC} | Status: ${status}"
        fi
    done
}

remove_tunnel_instance() {
    local instance_name="$1"
    if [[ -z "$instance_name" ]]; then
        list_active_tunnels
        read -rp "Enter instance name to remove (e.g. client-romania or server): " instance_name
    fi

    if [[ -z "$instance_name" ]]; then
        log_err "No instance specified."
        return
    fi

    systemctl stop "paqet@${instance_name}" 2>/dev/null || true
    systemctl disable "paqet@${instance_name}" 2>/dev/null || true
    rm -f "$CONFIG_DIR/${instance_name}.yaml"
    log_ok "Instance [${instance_name}] stopped and removed."
}

#-------------------------------------------------------------------------------
# Auto-Watchdog & Keepalive Subsystem
#-------------------------------------------------------------------------------
manage_watchdog() {
    while true; do
        clear 2>/dev/null || true
        local is_enabled="DISABLED"
        if systemctl is-active --quiet paqqet-watchdog.timer 2>/dev/null; then
            is_enabled="${GREEN}ACTIVE (Running every 3m)${NC}"
        else
            is_enabled="${RED}INACTIVE${NC}"
        fi

        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "${GREEN}${BOLD}             paQQet - AUTO WATCHDOG & KEEPALIVE                 ${NC}"
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "Current Status: $is_enabled"
        echo -e "Function: Automatically checks client raw packet flow every 3m."
        echo -e "If a tunnel drops packets, it restarts the instance automatically."
        echo -e "----------------------------------------------------------------"
        echo -e "  ${BOLD}1)${NC} Enable Auto-Watchdog Timer"
        echo -e "  ${BOLD}2)${NC} Disable Auto-Watchdog Timer"
        echo -e "  ${BOLD}3)${NC} View Watchdog Log (/var/log/paqqet-watchdog.log)"
        echo -e "  ${BOLD}0)${NC} Return to Main Menu"
        echo -e "${CYAN}================================================================${NC}"
        read -rp "Select option [0-3]: " w_choice

        case "$w_choice" in
            1)
                # Create Watchdog script
                cat > "$WATCHDOG_SCRIPT" << 'WDEOF'
#!/usr/bin/env bash
CONFIG_DIR="/etc/paqet"
BIN_PATH="/usr/local/bin/paqet"
LOG_FILE="/var/log/paqqet-watchdog.log"

for cfg in "$CONFIG_DIR"/client-*.yaml; do
    [[ -f "$cfg" ]] || continue
    bname=$(basename "$cfg" .yaml)
    svc="paqet@${bname}"

    if ! "$BIN_PATH" ping -c "$cfg" >/dev/null 2>&1; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] Tunnel ${bname} failed raw packet ping. Restarting ${svc}..." >> "$LOG_FILE"
        systemctl restart "$svc" 2>/dev/null || true
    fi
done
WDEOF
                chmod +x "$WATCHDOG_SCRIPT"

                cat > "$WATCHDOG_SERVICE" << 'WDEOF'
[Unit]
Description=paQQet Client Keepalive Watchdog
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/paqqet-watchdog.sh
WDEOF

                cat > "$WATCHDOG_TIMER" << 'WDEOF'
[Unit]
Description=Run paQQet Keepalive Watchdog every 3 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=3min
Unit=paqqet-watchdog.service

[Install]
WantedBy=timers.target
WDEOF

                systemctl daemon-reload
                systemctl enable --now paqqet-watchdog.timer
                log_ok "paQQet Keepalive Watchdog enabled and running every 3 minutes."
                pause_prompt
                ;;
            2)
                systemctl stop paqqet-watchdog.timer paqqet-watchdog.service 2>/dev/null || true
                systemctl disable paqqet-watchdog.timer paqqet-watchdog.service 2>/dev/null || true
                log_ok "Watchdog timer disabled."
                pause_prompt
                ;;
            3)
                echo -e "\n${BOLD}--- Watchdog Recent Logs ---${NC}"
                tail -n 25 /var/log/paqqet-watchdog.log 2>/dev/null || echo "No logs found yet."
                pause_prompt
                ;;
            0) return ;;
            *) log_err "Invalid selection."; sleep 1 ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# Backup & Restore Subsystem
#-------------------------------------------------------------------------------
manage_backup_restore() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "${GREEN}${BOLD}              paQQet - BACKUP & RESTORE CONFIGS                ${NC}"
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "  ${BOLD}1)${NC} Create Backup of all Tunnels & Keys (Saves to /root)"
        echo -e "  ${BOLD}2)${NC} Restore Tunnels from Backup Archive"
        echo -e "  ${BOLD}0)${NC} Return to Main Menu"
        echo -e "${CYAN}================================================================${NC}"
        read -rp "Select option [0-2]: " br_choice

        case "$br_choice" in
            1)
                mkdir -p "$CONFIG_DIR"
                local bk_file="/root/paqqet_backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                if tar -czf "$bk_file" -C /etc paqet 2>/dev/null; then
                    log_ok "Backup created successfully at: ${CYAN}${bk_file}${NC}"
                else
                    log_err "Failed to create backup."
                fi
                pause_prompt
                ;;
            2)
                echo -e "\nAvailable backups in /root:"
                ls -lh /root/paqqet_backup_*.tar.gz 2>/dev/null || echo "  (None found)"
                read -rp "Enter absolute path to backup tar.gz: " r_file
                if [[ -f "$r_file" ]]; then
                    tar -xzf "$r_file" -C /etc
                    systemctl daemon-reload
                    log_ok "Configurations restored successfully to $CONFIG_DIR."
                else
                    log_err "File not found: $r_file"
                fi
                pause_prompt
                ;;
            0) return ;;
            *) log_err "Invalid selection."; sleep 1 ;;
        esac
    done
}

#-------------------------------------------------------------------------------
# Live Packet & Traffic Monitor
#-------------------------------------------------------------------------------
monitor_live_traffic() {
    echo -e "\n${CYAN}${BOLD}=== LIVE PACKET & TRAFFIC MONITOR ===${NC}"
    list_active_tunnels
    echo ""
    read -rp "Enter tunnel name to inspect (e.g. client-romania or server): " mon_name
    local cfg="$CONFIG_DIR/${mon_name}.yaml"
    if [[ ! -f "$cfg" ]]; then
        log_err "Configuration file not found: $cfg"
        return
    fi

    local iface
    iface=$(grep -Po '(?<=interface:\s*")[^"]+' "$cfg" || true)
    echo -e "${YELLOW}[!] Launching live packet monitor on interface [${iface}]... (Press Ctrl+C to stop)${NC}\n"
    sleep 1

    if command -v tcpdump >/dev/null 2>&1; then
        tcpdump -i "$iface" -n "tcp or udp" -c 100 2>/dev/null || true
    else
        "$BIN_PATH" dump -c "$cfg" 2>/dev/null || true
    fi
}

#-------------------------------------------------------------------------------
# Interactive Terminal Menu
#-------------------------------------------------------------------------------
interactive_menu() {
    while true; do
        clear 2>/dev/null || true
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "${GREEN}${BOLD}           paQQet v3.1 - MULTI-TUNNEL ARCHITECTURE TOOL         ${NC}"
        echo -e "${CYAN}${BOLD}================================================================${NC}"
        echo -e "  ${BOLD}1)${NC} Install / Update Paqet Core (Download official binary & clean legacy)"
        echo -e "  ${BOLD}2)${NC} Setup Exit Server Node (Kharej Server - Listens for raw packets)"
        echo -e "  ${BOLD}3)${NC} Setup Client Hub Node (Iran Server - Connects to Kharej)"
        echo -e "  ${BOLD}4)${NC} Test Active Tunnel Connections (Raw Packet Ping & Service Status)"
        echo -e "  ${BOLD}5)${NC} Live Traffic & Packet Monitor (Inspect packet exchange in real-time)"
        echo -e "  ${BOLD}6)${NC} Optimize Linux OS & Network (BBR, Queue, Buffers & Limits)"
        echo -e "  ${BOLD}7)${NC} DNS Settings & Manager (Quad9, Cloudflare, Sanction Bypass)"
        echo -e "  ${BOLD}8)${NC} Auto-Watchdog & Keepalive (Automatic dead tunnel recovery)"
        echo -e "  ${BOLD}9)${NC} Backup & Restore Tunnel Configurations"
        echo -e " ${BOLD}10)${NC} List All Active Tunnels"
        echo -e " ${BOLD}11)${NC} Remove Specific Tunnel Instance"
        echo -e " ${BOLD}12)${NC} Uninstall paQQet Completely (Wipe all configs, services & binaries)"
        echo -e "  ${BOLD}0)${NC} Exit"
        echo -e "${CYAN}================================================================${NC}"
        read -rp "Select an option [0-12]: " choice

        case "$choice" in
            1)
                check_root
                detect_and_cleanup_legacy false
                install_dependencies
                ver=$(get_latest_paqet_version)
                download_paqet "$ver"
                pause_prompt
                ;;
            2)
                check_root
                echo -e "\n${BOLD}--- Setup Exit Server Node (Kharej) ---${NC}"
                read -rp "Instance Name [server]: " s_name
                s_name=${s_name:-server}
                read -rp "Listen Port [8443]: " s_port
                s_port=${s_port:-8443}
                read -rp "Secret Key (Leave empty to auto-generate): " s_key
                read -rp "MTU [1300]: " s_mtu
                s_mtu=${s_mtu:-1300}
                configure_server "$s_name" "$s_port" "$s_key" "$s_mtu"
                pause_prompt
                ;;
            3)
                check_root
                echo -e "\n${BOLD}--- Setup Client Node (Iran Hub) ---${NC}"
                read -rp "Target Exit Node Name (e.g. romania, hk): " c_name
                read -rp "Exit Server IP: " c_ip
                read -rp "Exit Server Port [8443]: " c_port
                c_port=${c_port:-8443}
                read -rp "Secret Key: " c_key
                read -rp "Local Listen Port on Iran [1080]: " c_lport
                c_lport=${c_lport:-1080}
                read -rp "Target Destination on Exit Server [127.0.0.1:1080]: " c_target
                c_target=${c_target:-"127.0.0.1:1080"}
                read -rp "MTU [1300]: " c_mtu
                c_mtu=${c_mtu:-1300}
                configure_client "$c_name" "$c_ip" "$c_port" "$c_key" "$c_lport" "$c_target" "$c_mtu"
                pause_prompt
                ;;
            4)
                test_tunnel_connectivity
                pause_prompt
                ;;
            5)
                monitor_live_traffic
                pause_prompt
                ;;
            6)
                check_root
                detect_network_details "8.8.8.8"
                apply_linux_optimizations
                pause_prompt
                ;;
            7)
                check_root
                manage_dns
                ;;
            8)
                check_root
                manage_watchdog
                ;;
            9)
                check_root
                manage_backup_restore
                ;;
            10)
                list_active_tunnels
                pause_prompt
                ;;
            11)
                check_root
                remove_tunnel_instance ""
                pause_prompt
                ;;
            12)
                check_root
                uninstall_paqqet_completely
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
            test)
                test_tunnel_connectivity
                ;;
            optimize)
                check_root
                detect_network_details "8.8.8.8"
                apply_linux_optimizations
                ;;
            uninstall)
                check_root
                uninstall_paqqet_completely
                ;;
            watchdog)
                check_root
                manage_watchdog
                ;;
            backup)
                check_root
                manage_backup_restore
                ;;
            *)
                echo "Usage: $0 {install|server|client|test|optimize|watchdog|backup|uninstall}"
                exit 1
                ;;
        esac
    fi
fi
