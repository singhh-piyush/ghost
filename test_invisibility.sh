#!/bin/bash
# Ghost Comprehensive Invisibility Test Suite
# Run with: sudo bash test_invisibility.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

echo "=== COMPREHENSIVE INVISIBILITY TEST ==="
echo ""

# Test 1: Hardware
echo -n "[1/15] Hardware invisibility... "
if ! ip netns exec ghost ls /sys/class/dmi/id/ 2>/dev/null | grep -q product_name; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ CAN SEE HARDWARE${NC}"; ((FAIL++))
fi

# Test 2: CPU
echo -n "[2/15] CPU fingerprinting... "
if ip netns exec ghost grep -q "i5-3470" /proc/cpuinfo 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ REAL CPU VISIBLE${NC}"; ((FAIL++))
fi

# Test 3: RAM
echo -n "[3/15] RAM fingerprinting... "
if ip netns exec ghost grep -q "8192000 kB" /proc/meminfo 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ REAL RAM VISIBLE${NC}"; ((FAIL++))
fi

# Test 4: Kernel version
echo -n "[4/15] Kernel version hiding... "
if ip netns exec ghost grep -q "5.15.0-generic" /proc/version 2>/dev/null; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${YELLOW}⚠ REAL KERNEL VISIBLE${NC}"; ((FAIL++))
fi

# Test 5: IPv6
echo -n "[5/15] IPv6 blocking... "
if ! ip netns exec ghost timeout 2 curl -6 -s ifconfig.co 2>&1 | grep -qE '^[0-9a-f:]+$'; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ IPv6 LEAK${NC}"; ((FAIL++))
fi

# Test 6: DNS
echo -n "[6/15] DNS isolation... "
if ! ip netns exec ghost timeout 2 dig +short @8.8.8.8 google.com 2>&1 | grep -qE '^[0-9]+\.'; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ DNS LEAK${NC}"; ((FAIL++))
fi

# Test 7: Raw sockets
echo -n "[7/15] Raw socket blocking... "
if ip netns exec ghost python3 -c "import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW)" 2>&1 | grep -q "not permitted"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ RAW SOCKETS ALLOWED${NC}"; ((FAIL++))
fi

# Test 8: Seccomp
echo -n "[8/15] Seccomp active... "
if ip netns exec ghost cat /proc/self/status 2>/dev/null | grep -q "Seccomp:.*2"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ SECCOMP INACTIVE${NC}"; ((FAIL++))
fi

# Test 9: Mount operations
echo -n "[9/15] Mount blocking... "
if ip netns exec ghost mount -t tmpfs tmpfs /tmp/test 2>&1 | grep -q "not permitted\|denied"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ MOUNT ALLOWED${NC}"; ((FAIL++))
fi

# Test 10: Filesystem writes
echo -n "[10/15] Filesystem restrictions... "
if ip netns exec ghost touch /usr/bin/ghost_test 2>&1 | grep -q "Permission denied\|Read-only\|not permitted"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ CAN WRITE TO /usr${NC}"; ((FAIL++))
    rm -f /usr/bin/ghost_test 2>/dev/null
fi

# Test 11: Tmpfs home
echo -n "[11/15] Tmpfs home... "
if ip netns exec ghost mount 2>/dev/null | grep -q "tmpfs.*ghost_home"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${YELLOW}⚠ NOT TMPFS${NC}"; ((FAIL++))
fi

# Test 12: Display variables
echo -n "[12/15] Display isolation... "
if [[ -z "$(ip netns exec ghost bash -c 'echo $DISPLAY' 2>/dev/null)" ]]; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ DISPLAY SET${NC}"; ((FAIL++))
fi

# Test 13: Process visibility
echo -n "[13/15] Process isolation... "
PROCS=$(ip netns exec ghost ps aux 2>/dev/null | wc -l)
if [[ $PROCS -lt 20 ]]; then
    echo -e "${GREEN}✓ (only $PROCS processes)${NC}"; ((PASS++))
else
    echo -e "${RED}✗ CAN SEE $PROCS PROCESSES${NC}"; ((FAIL++))
fi

# Test 14: Tor connectivity
echo -n "[14/15] Tor connection... "
if timeout 10 curl -s https://check.torproject.org/api/ip 2>/dev/null | grep -q "IsTor.*true"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${RED}✗ NOT CONNECTED TO TOR${NC}"; ((FAIL++))
fi

# Test 15: Capabilities
echo -n "[15/15] Capabilities dropped... "
if ip netns exec ghost cat /proc/self/status 2>/dev/null | grep -q "CapEff:.*0000000000000000"; then
    echo -e "${GREEN}✓${NC}"; ((PASS++))
else
    echo -e "${YELLOW}⚠ SOME CAPS REMAIN${NC}"; ((FAIL++))
fi

echo ""
echo "=========================================="
echo "SCORE: $PASS/15 passed, $FAIL/15 failed"
echo "=========================================="

if [[ $PASS -eq 15 ]]; then
    echo "PERFECT! All invisibility features working."
    exit 0
elif [[ $PASS -ge 12 ]]; then
    echo "GOOD - Minor issues only."
    exit 0
else
    echo "FAILED - Critical issues found."
    exit 1
fi
