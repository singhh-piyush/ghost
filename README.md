> **WORK IN PROGRESS**
> Ghost is under active development. There are known mitigations missing and likely undiscovered edge cases.

<pre>
  ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗
  ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝
  ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░
  ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░
  ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░
  ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░
</pre>

Sandboxed Linux environment that routes all traffic through Tor.

```bash
sudo ghost
```

---

## Security Layers

| Layer | What It Does |
|---|---|
| Network Namespace | Isolated network stack |
| Tor | All TCP transparently proxied through a dedicated Tor instance |
| DNS | Routed through Tor. Direct resolvers blocked |
| IPv6 | Fully disabled |
| Landlock | Filesystem access restricted to whitelisted paths |
| Seccomp | Blocks raw sockets, ptrace, mount, BPF, io_uring, kernel modules |
| Capabilities | Dangerous caps dropped before exec |
| MAC Address | Randomised on every run |
| WebRTC | STUN/TURN ports blocked |
| Hardware Spoofing | Fake `/proc/cpuinfo`, `/proc/meminfo`, `/proc/version` bind-mounted inside shell |
| `/sys` | Replaced with empty tmpfs inside shell |
| Home Directory | tmpfs-backed, RAM only, never touches disk |
| Session Logs | HMAC-chained, stored in ramfs |

---

## Requirements

**Arch Linux**
```bash
sudo pacman -S gcc make libseccomp tor libcap iproute2 iptables-nft
```

**Debian/Ubuntu**
```bash
sudo apt install build-essential libseccomp-dev tor libcap-bin iproute2 iptables
```

- Linux kernel 5.13+ (Landlock)
- `unshare`, `script`, `sudo`

---

## Install

```bash
sudo bash install.sh
```

---

## Usage

```bash
sudo ghost                  # Interactive menu
sudo ghost start            # Start sandbox
sudo ghost stop             # Stop and clean up
sudo ghost shell            # Shell inside sandbox
sudo ghost status           # Current status
sudo ghost identity         # Rotate Tor circuit
sudo ghost country          # Set exit node country
sudo ghost health           # Full diagnostics
sudo ghost cover            # Cover traffic generator
sudo ghost nuke             # Force reset
sudo ghost report           # Export security report to /tmp
```

```bash
sudo GHOST_PROFILE=paranoid ghost start   # Use a profile
```

Profiles: `/etc/ghost/profiles/` - Custom Tor config: `/etc/ghost/custom.torrc`

---

## Config

`/etc/ghost/config` - key options:

| Option | Default | Description |
|---|---|---|
| `TOR_MODE` | `dedicated` | `dedicated` or `system` |
| `TOR_BRIDGES` | `none` | `none`, `obfs4`, `vanilla`, `snowflake` |
| `HIDE_HARDWARE` | `1` | Spoof `/proc` hardware entries |
| `TMPFS_HOME` | `1` | RAM-backed home |
| `ENABLE_SECCOMP` | `1` | Seccomp-BPF filter |
| `ENABLE_LANDLOCK` | `1` | Landlock filesystem restrictions |
| `ENABLE_CAPS_DROP` | `1` | Drop capabilities before exec |
| `ENABLE_COVER_TRAFFIC` | `0` | Background cover traffic |
| `AUTO_IDENTITY_ROTATION` | `0` | Periodic exit node rotation |

---

## Test

```bash
sudo bash test_invisibility.sh
```

15 checks: IPv6, DNS, raw sockets, Seccomp, Landlock, capabilities, Tor connectivity, and more. Run while Ghost is active.

---

## Limitations

- Hardware spoofing only applies inside `ghost shell`, not system-wide.
- Application-layer leaks (browser headers, cookies, fingerprinting) are not covered.
- Landlock silently skipped on kernels below 5.13. Seccomp skipped if `libseccomp` missing at compile time.
- Time jitter not yet implemented - clock-based fingerprinting is not mitigated. Planned.
- Requires root to set up the namespace.

---

## Uninstall

```bash
sudo rm -f /usr/local/bin/ghost && sudo rm -rf /usr/local/lib/ghost /etc/ghost
```
