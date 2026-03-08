#!/bin/bash
set -euo pipefail

GHOST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Ghost..."

# Check for existing Tor config
if [[ -f /etc/tor/torrc ]]; then
    echo "[!] Existing Tor configuration detected at /etc/tor/torrc"
    echo "    Ghost can use its own dedicated Tor instance (recommended)"
    echo "    or attempt to coexist with system Tor."
    echo ""
    # read -p "Use dedicated Tor instance? [Y/n]: " choice
    choice="Y"
    echo "Using dedicated Tor instance by default."
    
    if [[ "$choice" =~ ^[Nn]$ ]]; then
        echo "[!] Skipping Tor configuration."
        echo "    You must manually configure /etc/tor/torrc:"
        echo "    TransPort 127.0.0.1:9040"
        echo "    DNSPort 127.0.0.1:5353"
    fi
fi

# Determine lib directory
# We install to /usr/local/lib/ghost/ (root of our libraries)
# Ghost script expects DIR/lib and DIR/banner.txt
LIB_ROOT="/usr/local/lib/ghost"

echo "[+] Ghost will be installed to $LIB_ROOT"

# [FIX 16.3] Pre-compile security modules
echo "    Compiling security modules..."
if make -C "$GHOST_DIR" >/dev/null 2>&1; then
    echo "    Compilation successful."
else
    echo "    [WARNING] Compilation failed. Some security features (Seccomp/Landlock) may be disabled."
    echo "    Ensure 'build-essential' and 'libseccomp-dev' are installed."
fi

# Install binaries
mkdir -p /usr/local/bin
echo "    Copying ghost executable..."
rm -f /usr/local/bin/ghost
cp "$GHOST_DIR/ghost" /usr/local/bin/ghost
chmod 755 /usr/local/bin/ghost

# Install libraries and assets
# [FIX 15.2] Clean directory structure (flatten lib, include banner)
mkdir -p "$LIB_ROOT"
# Remove old installation if exists to prevent nesting/confusion
rm -rf "$LIB_ROOT"
mkdir -p "$LIB_ROOT"

echo "    Copying resources to $LIB_ROOT..."

# Copy lib directory (as a subdirectory, because ghost expects $DIR/lib)
cp -r "$GHOST_DIR/lib" "$LIB_ROOT/"

# Copy banner.txt (ghost expects $DIR/banner.txt)
if [[ -f "$GHOST_DIR/banner.txt" ]]; then
    cp "$GHOST_DIR/banner.txt" "$LIB_ROOT/"
fi

# Update ghost script to point DIR to the library root
# Ghost expects DIR/lib/... and DIR/banner.txt
sed -i "s|^DIR=.*|DIR=\"$LIB_ROOT\"|" /usr/local/bin/ghost

# Install configuration files
echo "    Installing configuration..."
mkdir -p /etc/ghost/profiles

if [[ ! -f /etc/ghost/config ]]; then
    cp "$GHOST_DIR/ghost.conf" /etc/ghost/config
    echo "    Created /etc/ghost/config (default configuration)"
else
    echo "    /etc/ghost/config exists, skipping (won't overwrite)"
fi

# Install profile configs
if [[ -d "$GHOST_DIR/profiles" ]]; then
    cp "$GHOST_DIR/profiles/"*.conf /etc/ghost/profiles/ 2>/dev/null || true
    echo "    Installed profiles: $(ls /etc/ghost/profiles/ 2>/dev/null | tr '\n' ' ')"
fi

# Run verification if available
if [[ -f "$GHOST_DIR/verify_installation.sh" ]]; then
    echo ""
    echo "[*] Running installation verification..."
    bash "$GHOST_DIR/verify_installation.sh" || true
fi

echo ""
echo "[+] Installation complete. Run 'sudo ghost' to start."
echo "    Config: /etc/ghost/config"
echo "    Profiles: /etc/ghost/profiles/"
echo "    Usage: sudo GHOST_PROFILE=paranoid ghost start"
