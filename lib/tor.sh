#!/bin/bash
# Ghost Dedicated Tor Instance Manager
set -e

GHOST_TOR_DIR="/run/ghost/tor"
GHOST_TORRC="/run/ghost/torrc"
GHOST_TOR_PID="/run/ghost/tor.pid"
GHOST_TOR_LOG="/run/ghost/tor.log"

tor_generate_config() {
    local extra_config="${1:-}"
    
    cat > "$GHOST_TORRC" <<EOF
# Ghost Dedicated Tor Instance
DataDirectory $GHOST_TOR_DIR

# Disable SOCKS (we use transparent proxy)
SocksPort 0

# Transparent proxy with per-target circuit isolation
TransPort 127.0.0.1:9040 IsolateDestAddr IsolateDestPort

# DNS with isolation
DNSPort 127.0.0.1:5353 IsolateDestAddr

# Control
ControlPort 127.0.0.1:9051
CookieAuthentication 1

# Security
RunAsDaemon 0
Log notice file $GHOST_TOR_LOG
AvoidDiskWrites 1
SafeLogging 1

# Circuit building
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600

# [FIX 16.4] Run as dedicated user (avoid root)
User $TOR_USER

$extra_config
EOF

    # [FEATURE] Allow Custom User Configuration
    # If a custom torrc snippet exists, append it to the configuration
    local custom_rc="/etc/ghost/custom.torrc"
    if [[ -f "$custom_rc" ]]; then
        echo "# --- Custom Configuration from $custom_rc ---" >> "$GHOST_TORRC"
        cat "$custom_rc" >> "$GHOST_TORRC"
    fi

    chmod 600 "$GHOST_TORRC"
    chown "$TOR_USER" "$GHOST_TORRC"
}

# Detect proper Tor user
if id "debian-tor" &>/dev/null; then
    TOR_USER="debian-tor"
elif id "tor" &>/dev/null; then
    TOR_USER="tor"
else
    # [FIX 17.2] Create dedicated user if none found
    if ! id "ghost-tor" &>/dev/null; then
        echo "Creating dedicated ghost-tor user..." >&2
        useradd --system --home-dir /run/ghost --shell /bin/false ghost-tor 2>/dev/null || true
    fi
    TOR_USER="ghost-tor"
fi

tor_start() {
    # [FIX] Detect port conflicts BEFORE attempting to start
    local ports_in_use=""
    
    if ss -tuln 2>/dev/null | grep -q ":9040 "; then
        ports_in_use="$ports_in_use 9040(TransPort)"
    fi
    if ss -tuln 2>/dev/null | grep -q ":5353 "; then
        ports_in_use="$ports_in_use 5353(DNSPort)"
    fi
    if ss -tuln 2>/dev/null | grep -q ":9051 "; then
        ports_in_use="$ports_in_use 9051(ControlPort)"
    fi
    
    if [[ -n "$ports_in_use" ]]; then
        echo "ERROR: Tor ports already in use:$ports_in_use" >&2
        echo "System Tor is likely running. Stop it with:" >&2
        echo "  sudo systemctl stop tor" >&2
        echo "  sudo systemctl disable tor" >&2
        return 1
    fi

    mkdir -p "$GHOST_TOR_DIR"
    chmod 700 "$GHOST_TOR_DIR"
    chown -R "$TOR_USER" "$GHOST_TOR_DIR"
    
    # Generate config
    tor_generate_config "$1"
    
    # Start Tor in background
    tor -f "$GHOST_TORRC" &
    local pid=$!
    
    # Verify process actually started
    sleep 0.5
    if ! kill -0 $pid 2>/dev/null; then
        echo "Error: Tor failed to start" >&2
        rm -f "$GHOST_TORRC"
        return 1
    fi
    
    echo $pid > "$GHOST_TOR_PID"
    
    # Wait for bootstrap
    tor_wait_bootstrap
}

tor_wait_bootstrap() {
    local timeout=45
    local i
    
    echo -n "Waiting for Tor bootstrap..."
    for ((i=0; i<timeout; i++)); do
        if [[ -f "$GHOST_TOR_LOG" ]] && grep -q "Bootstrapped 100%" "$GHOST_TOR_LOG" 2>/dev/null; then
            echo " OK"
            return 0
        fi
        sleep 1
    done
    
    echo " TIMEOUT"
    return 1
}

tor_stop() {
    if [[ -f "$GHOST_TOR_PID" ]]; then
        local pid
        pid=$(cat "$GHOST_TOR_PID")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            # Wait for clean shutdown
            local i
            for ((i=0; i<10; i++)); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.2
            done
            # Force kill if still running
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$GHOST_TOR_PID"
    fi
    rm -rf "$GHOST_TOR_DIR" "$GHOST_TORRC" "$GHOST_TOR_LOG"
}

tor_is_running() {
    [[ -f "$GHOST_TOR_PID" ]] && kill -0 "$(cat "$GHOST_TOR_PID")" 2>/dev/null
}

tor_get_auth_cookie() {
    local cookie_path="$GHOST_TOR_DIR/control_auth_cookie"
    if [[ -f "$cookie_path" ]]; then
        xxd -p "$cookie_path" | tr -d '\n'
    fi
}

tor_signal_newnym() {
    local cookie
    cookie=$(tor_get_auth_cookie)
    if [[ -n "$cookie" ]]; then
        ( echo -e "AUTHENTICATE $cookie\r\nSIGNAL NEWNYM\r\nQUIT" > /dev/tcp/127.0.0.1/9051 ) 2>/dev/null
        return $?
    fi
    return 1
}

tor_set_country() {
    local country="$1"
    tor_stop
    tor_start "ExitNodes {$country}
StrictNodes 1"
}

# Bridge support for censored networks
tor_use_bridges() {
    local bridge_type="${1:-obfs4}"
    local bridge_config=""
    
    case "$bridge_type" in
        obfs4)
            bridge_config="UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 auto"
            ;;
        vanilla)
            bridge_config="UseBridges 1
Bridge auto"
            ;;
        snowflake)
            bridge_config="UseBridges 1
ClientTransportPlugin snowflake exec /usr/bin/snowflake-client -url https://snowflake-broker.torproject.net.global.prod.fastly.net/ -front cdn.sstatic.net -ice stun:stun.l.google.com:19302,stun:stun.voip.blackberry.com:3478,stun:stun.altar.com.pl:3478,stun:stun.antisip.com:3478,stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,stun:stun.epygi.com:3478,stun:stun.sonetel.com:3478,stun:stun.sonetel.net:3478,stun:stun.stunprotocol.org:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.voys.nl:3478
Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72"
            ;;
        *)
            echo "Unknown bridge type: $bridge_type" >&2
            echo "Supported: obfs4, vanilla, snowflake" >&2
            return 1
            ;;
    esac
    
    tor_stop
    tor_start "$bridge_config"
    echo "Bridges enabled: $bridge_type"
}

# Limit bandwidth to avoid detection
tor_set_bandwidth() {
    local rate="${1:-500}"  # KB/s
    local burst="${2:-1000}" # KB/s
    
    tor_stop
    tor_start "RelayBandwidthRate ${rate} KB
RelayBandwidthBurst ${burst} KB"
    
    echo "Bandwidth limited to ${rate}KB/s (burst: ${burst}KB/s)"
}

# Use specific entry guards
tor_set_guards() {
    local guards="$1"  # Comma-separated fingerprints
    
    tor_stop
    tor_start "EntryNodes $guards
StrictNodes 1"
    
    echo "Entry guards set to: $guards"
}

# CLI interface
case "${1:-}" in
    start) tor_start "${2:-}" ;;
    stop) tor_stop ;;
    status) tor_is_running && echo "running" || echo "stopped" ;;
    newnym) tor_signal_newnym ;;
    country) tor_set_country "$2" ;;
    bridges) tor_use_bridges "${2:-obfs4}" ;;
    bandwidth) tor_set_bandwidth "${2:-500}" "${3:-1000}" ;;
    guards) tor_set_guards "$2" ;;
    *) echo "Usage: tor.sh {start|stop|status|newnym|country <cc>|bridges <type>|bandwidth <rate> [burst]|guards <fingerprints>}" >&2 ;;
esac
