#!/bin/bash
set -e
REAL_USER=${1:-${SUDO_USER:-$USER}}
DIR="/usr/local/lib/ghost"
NS="ghost"
VETH_HOST="veth0"
VETH_JAIL="veth1"
HOST_IP="10.200.200.1"
JAIL_IP="10.200.200.2"

ip netns del "$NS" 2>/dev/null || true
ip link delete "$VETH_HOST" 2>/dev/null || true

ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_JAIL"
ip link set "$VETH_JAIL" netns "$NS"

# Robust MAC address generation
gen_mac() {
    local hex
    # Try openssl
    if command -v openssl &>/dev/null; then
        hex=$(openssl rand -hex 5 2>/dev/null | sed 's/\(..\)/\1:/g; s/:$//')
    fi
    
    # Fallback to od if openssl failed/missing
    if [[ -z "$hex" || ${#hex} -ne 14 ]]; then
        if command -v od &>/dev/null; then
            hex=$(od -An -N5 -tx1 /dev/urandom 2>/dev/null | tr -d ' ' | tr -d '\n' | sed 's/\(..\)/\1:/g; s/:$//')
        fi
    fi

    # Final fallback if both fail
    if [[ -z "$hex" || ${#hex} -ne 14 ]]; then
        hex="a1:b2:c3:d4:e5"
    fi
    
    echo "02:$hex"
}

ip netns exec "$NS" ip link set dev "$VETH_JAIL" address "$(gen_mac)"

ip addr add "$HOST_IP/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

# ============================================
# [FIX 1.2] IPv6 Hardening - COMPLETE BLOCK
# Disable IPv6 BEFORE bringing namespace interfaces up to prevent link-local assignment
# ============================================
ip netns exec "$NS" sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv6.conf."$VETH_JAIL".disable_ipv6=1 >/dev/null 2>&1

# NOW bring up interfaces and assign IP (after IPv6 is disabled)
ip netns exec "$NS" ip addr add "$JAIL_IP/24" dev "$VETH_JAIL"
ip netns exec "$NS" ip link set lo up

# Flush any existing IPv6 addresses (belt-and-suspenders)
ip netns exec "$NS" ip -6 addr flush dev "$VETH_JAIL" 2>/dev/null || true
ip netns exec "$NS" ip -6 addr flush dev lo 2>/dev/null || true

# Complete IPv6 firewall block
if command -v ip6tables &>/dev/null; then
    ip netns exec "$NS" ip6tables -F 2>/dev/null || true
    ip netns exec "$NS" ip6tables -P INPUT DROP 2>/dev/null || true
    ip netns exec "$NS" ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip netns exec "$NS" ip6tables -P FORWARD DROP 2>/dev/null || true
    
    # Block ICMPv6 Router Advertisement/Solicitation to prevent link-local assignment
    ip netns exec "$NS" ip6tables -A INPUT -p icmpv6 --icmpv6-type 134 -j DROP 2>/dev/null || true  # Router Advertisement
    ip netns exec "$NS" ip6tables -A INPUT -p icmpv6 --icmpv6-type 133 -j DROP 2>/dev/null || true  # Router Solicitation
    ip netns exec "$NS" ip6tables -A INPUT -p icmpv6 --icmpv6-type 135 -j DROP 2>/dev/null || true  # Neighbor Solicitation
    ip netns exec "$NS" ip6tables -A INPUT -p icmpv6 --icmpv6-type 136 -j DROP 2>/dev/null || true  # Neighbor Advertisement
fi

# ============================================
# IPv4 Hardening inside namespace
# ============================================
if command -v iptables &>/dev/null; then
    ip netns exec "$NS" iptables -F 2>/dev/null || true
    ip netns exec "$NS" iptables -P INPUT DROP 2>/dev/null || true
    ip netns exec "$NS" iptables -P FORWARD DROP 2>/dev/null || true
    ip netns exec "$NS" iptables -P OUTPUT DROP 2>/dev/null || true
    
    # Allow loopback
    ip netns exec "$NS" iptables -A INPUT -i lo -j ACCEPT
    ip netns exec "$NS" iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow return traffic
    ip netns exec "$NS" iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Block known DoH (DNS over HTTPS) providers to prevent DNS bypass
    # Cloudflare
    ip netns exec "$NS" iptables -A OUTPUT -d 1.1.1.1 -p tcp --dport 443 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -d 1.0.0.1 -p tcp --dport 443 -j DROP
    # Google
    ip netns exec "$NS" iptables -A OUTPUT -d 8.8.8.8 -p tcp --dport 443 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -d 8.8.4.4 -p tcp --dport 443 -j DROP
    # Quad9
    ip netns exec "$NS" iptables -A OUTPUT -d 9.9.9.9 -p tcp --dport 443 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -d 149.112.112.112 -p tcp --dport 443 -j DROP
    # OpenDNS
    ip netns exec "$NS" iptables -A OUTPUT -d 208.67.222.222 -p tcp --dport 443 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -d 208.67.220.220 -p tcp --dport 443 -j DROP
    # NextDNS
    ip netns exec "$NS" iptables -A OUTPUT -d 45.90.28.0 -p tcp --dport 443 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -d 45.90.30.0 -p tcp --dport 443 -j DROP

    # Block Tor Control/Socks Ports FIRST (insert at top to take precedence)
    ip netns exec "$NS" iptables -I OUTPUT 1 -p tcp --dport 9050 -j DROP
    ip netns exec "$NS" iptables -I OUTPUT 2 -p tcp --dport 9051 -j DROP

    # Allow TCP out (will be redirected to Tor by host NAT)
    ip netns exec "$NS" iptables -A OUTPUT -p tcp -j ACCEPT
    
    # [FIX 1.4] UDP DNS - ONLY to our DNS proxy, not arbitrary resolvers
    ip netns exec "$NS" iptables -A OUTPUT -p udp -d "$HOST_IP" --dport 53 -j ACCEPT
    ip netns exec "$NS" iptables -A OUTPUT -p udp --dport 53 -j DROP  # Block all other DNS

    # ============================================
    # [FIX 4.1] WebRTC Leak Prevention
    # ============================================
    # Block STUN/TURN ports used by browsers to leak local IP
    ip netns exec "$NS" iptables -A OUTPUT -p udp --dport 3478 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -p udp --dport 5349 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -p tcp --dport 3478 -j DROP
    ip netns exec "$NS" iptables -A OUTPUT -p tcp --dport 5349 -j DROP

    # ============================================
    # [FIX 4.2] FTP Active Mode Prevention
    # ============================================
    # Block incoming connections to high ports (Active FTP data channel) from port 20
    ip netns exec "$NS" iptables -A INPUT -p tcp --sport 20 -j DROP
fi

# ============================================
# [FIX 4.3] ICMP Redirect Attack Prevention
# ============================================
# Disable accepting redirects to prevent route manipulation
ip netns exec "$NS" sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv4.conf.all.secure_redirects=0 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
ip netns exec "$NS" sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1

ip netns exec "$NS" ip link set "$VETH_JAIL" up
ip netns exec "$NS" ip route add default via "$HOST_IP"

# DNS resolution config
mkdir -p "/etc/netns/$NS"
echo "nameserver $HOST_IP" > "/etc/netns/$NS/resolv.conf"

if command -v chattr &>/dev/null; then
    if ! chattr +i "/etc/netns/$NS/resolv.conf" 2>/dev/null; then
        chmod 444 "/etc/netns/$NS/resolv.conf"
    fi
else
    chmod 444 "/etc/netns/$NS/resolv.conf"
fi

# ============================================
# [FIX 1.1] /etc/hosts Leak Prevention
# ============================================
# Create minimal hosts file for namespace to prevent DNS bypass via hardcoded IPs
mkdir -p "/etc/netns/$NS"
cat > "/etc/netns/$NS/hosts" << 'EOF'
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
EOF
chmod 444 "/etc/netns/$NS/hosts"
# Make immutable if possible
chattr +i "/etc/netns/$NS/hosts" 2>/dev/null || true

# ============================================
# Timezone (UTC) to prevent timezone leaks
# ============================================
if [[ -f /usr/share/zoneinfo/UTC ]]; then
    cp /usr/share/zoneinfo/UTC "/etc/netns/$NS/localtime"
fi

# ============================================
# [FIX 1.5] Time Jitter - Prevent NTF fingerprinting
# ============================================
# Add random time offset (±30 minutes) inside namespace to prevent time correlation attacks
# This is applied when entering the namespace, not here, to avoid clock drift issues

# Enable forwarding and localnet routing
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null

# Traffic Shaping (Obfuscation) to smooth bursty scans
if command -v tc &>/dev/null; then
    ip netns exec "$NS" tc qdisc add dev "$VETH_JAIL" root tbf rate 800kbit burst 5kb latency 100ms 2>/dev/null
fi

echo "[+] Namespace constructed: $JAIL_IP (UTC timezone, hosts hardened)"