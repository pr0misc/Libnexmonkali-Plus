# Libnexmonkali-Plus 🚀

> A high-performance, universal Nexmon userspace library for Broadcom Wi-Fi chips — supporting both **AArch64** (Samsung S10/S21+, modern phones) and **ARMHF** (TicWatch Pro/Pro3, Raspberry Pi).

## 📖 Overview

This library intercepts system calls via `LD_PRELOAD` to enable monitor mode, frame injection, and channel switching on Nexmon-patched Broadcom chips. It works with both **bcmdhd** (Samsung) and **brcmfmac** (TicWatch/RPi) kernel drivers, automatically detecting the correct injection method at runtime.

### Supported Devices

| Device | Chip | Driver | Arch | Injection Method |
|---|---|---|---|---|
| Samsung S10/S21+ | BCM4375b1 | `bcmdhd` | aarch64 | `NEX_INJECT_FRAME` IOCTL |
| TicWatch Pro/Pro3 | BCM43436b0 | `brcmfmac` | armhf | Raw socket → `wl_send_hook` |
| Raspberry Pi (64-bit) | Various | `brcmfmac` | aarch64 | Raw socket → `wl_send_hook` |
| Raspberry Pi (32-bit) | Various | `brcmfmac` | armhf | Raw socket → `wl_send_hook` |

### Supported Tools

| Tool | Use Case | Auto-Delay |
|---|---|---|
| Reaver / Bully | WPS attacks | 5ms |
| hcxdumptool | PMKID/Handshake capture | 10ms |
| aireplay-ng | Deauth / Injection | 15ms |
| Kismet | Scanning / Monitoring | 20ms |
| airodump-ng | Channel hopping / Scanning | 40ms |
| All others | General use | 70ms (safe) |

## ⚡ Key Features

### 1. Universal Packet Injection
Hooks all major packet transmission syscalls: `write()`, `sendto()`, `sendmsg()`, `send()`, `sendmmsg()`. On **bcmdhd** devices, frames are routed through `NEX_INJECT_FRAME` IOCTL. On **brcmfmac** devices (TicWatch/RPi), frames pass through to the kernel where the firmware's `wl_send_hook` handles injection.

### 2. Automatic Driver Detection
On init, the library probes `/sys/module/brcmfmac/` and `/sys/module/bcmdhd/` to determine which driver is loaded and selects the correct injection method. Falls back to architecture-based defaults (`armhf` → raw socket, `aarch64` → IOCTL).

### 3. Reliable Handshake Capture
Forces `WLC_SET_PM=0` (Constantly Awake Mode) to prevent the chip from sleeping during EAPOL handshakes. Promiscuous mode (`WLC_SET_PROMISC=1`) is enforced after every channel change.

### 4. Smart Speed (Auto-Optimization)
Inspects `/proc/self/comm` to detect the running tool and automatically sets the optimal injection delay. Can be overridden with the `NEXMON_DELAY` environment variable.

### 5. Channel Switching Stability
Re-enforces wake and promiscuous state after every channel change. For Kismet and hcxdumptool, periodic stability enforcement runs every 50 injected frames.

### 6. Kismet & hcxdumptool Bypass
- Fakes `NL80211_CMD_SET_INTERFACE` success (prevents "can't set monitor mode" errors)
- Suppresses `EOPNOTSUPP`/`EINVAL` netlink errors on read (prevents tool abort)
- Forces `SIOCSIWMODE` success for Kismet's legacy monitor mode path

### 7. Configurable Interface
Set `NEXMON_IFACE` environment variable to override the default `wlan0` interface name.

## 🛠️ Build & Install

### Prerequisites
- Cross-compiler: `aarch64-linux-gnu-gcc` and/or `arm-linux-gnueabihf-gcc`
- libnl3 development headers: `apt install libnl-3-dev libnl-genl-3-dev`

### Build

```bash
# For Samsung S10/S21+ and modern 64-bit devices
make aarch64

# For TicWatch Pro/Pro3 and 32-bit ARM devices
make armhf

# Install globally (copies to /usr/lib/ and /usr/bin/)
sudo make install
```

## 💻 Usage

### Step 1: Enable Monitor Mode (Device Side)
```bash
nexutil -m2     # or: nexutil -s0x613 -i -v2
```

### Step 2: Run Tools

**Option A: Single Command (Recommended)**
```bash
# Auto-detect speed (let library choose optimal delay per tool)
nxsp 0 reaver -i wlan0 -b <BSSID> -c <CH>

# Manual delay override (e.g., 15ms)
nxsp 15 mdk4 wlan0 d
```

**Option B: Shell Mode**
```bash
# Enter Nexmon shell (smart auto-detect per tool)
nxsp load

# Run tools — each tool gets its own optimal delay automatically
reaver -i wlan0 ...
airodump-ng wlan0

# Exit
exit
```

**Option C: Direct LD_PRELOAD**
```bash
NEXMON_DELAY=0 LD_PRELOAD=/usr/lib/libnexmonkali.so reaver -i wlan0 ...
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NEXMON_DELAY` | Auto-detect | Injection delay in nanoseconds (0 = no delay) |
| `NEXMON_IFACE` | `wlan0` | Override interface name |

## ⚠️ Disclaimer

This software is for educational purposes and authorized security auditing only. The authors are not responsible for any misuse or damage caused by this software. Ensure you comply with all local laws and regulations regarding radio transmission and network security.

## 🏆 Credits

- Original Work: [Nexmon Team](https://github.com/seemoo-lab/nexmon)
- Inspiration & Motivation: [yesimxev](https://github.com/yesimxev)
- Original Library: [RoninNada](https://github.com/RoninNada/libnexmonkali)
- S10 Optimization & Fork: [qazianwar222](https://github.com/pr0misc)
