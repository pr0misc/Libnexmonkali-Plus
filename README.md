# libnexmonkali (Samsung S10 Optimized)

This is a heavily modified version of `libnexmonkali`, specifically optimized for the Samsung S10 (and similar Broadcom-based devices) to ensure full functionality with modern penetration testing tools like `Reaver`, `Aireplay-ng`, `Airodump-ng`, and `Kismet`.

## 🚀 Key Modifications & Features

### 1. Universal Packet Injection Support
The original library only intercepted `write()` calls, which caused tools like `Reaver` to fail injection. This version implements hooks for **all** packet transmission system calls:
- `write()`
- `sendto()` (Used by Reaver)
- `sendmsg()`
- `send()`
- `sendmmsg()`

All trapped packets are automatically encapsulated and injected via the custom Broadcom `NEX_INJECT_FRAME` IOCTL, ensuring full compatibility with the complete Aircrack-ng suite and Reaver.

### 2. Reliable Handshake Capture (Power Management Fix)
We addressed a critical issue where the wifi chip would sleep while waiting for DTIM beacons, causing it to miss EAPOL M2/M4 packets during a handshake capture. 

**The Modification:** We added an explicit `WLC_SET_PM = 0` (Constantly Awake Mode) command during initialization. This ensures the radio stays awake to capture 100% of frames, fixing issues with missing 4-way handshakes.

### 3. Extended Range (TX Power Boost)
To address reception and injection range issues, we added an automatic `WLC_SET_TXPWR` command (configured to `500`) during the interface initialization. This overrides default power saving limits to maximize transmission power.

---

## 🛠️ Complete Usage Guide

### 1. Build
You need an `aarch64` cross-compiler or a native environment (Termux/Kali Chroot).

```bash
# Clean previous builds
make clean

# Compile the shared library
make
```

### 2. Install
Copy the compiled `libnexmonkali.so` to your device (e.g., in your home folder or a dedicated directory).

```bash
cp libnexmonkali.so /root/libnexmonkali.so
```

### 3. Running Tools
You must **preload** the library whenever you run a wifi-related tool.

#### Enable Monitor Mode
This step is crucial as it initializes our custom IOCTLs (Power Boost, CAM, etc.).
```bash
LD_PRELOAD=/root/libnexmonkali.so AIRMON_NG=1 airmon-ng start wlan0
```

#### Packet Injection (Reaver/Aireplay-ng)
Reaver will now work correctly due to the `sendto`/`send` hooks.
```bash
LD_PRELOAD=/root/libnexmonkali.so reaver -i wlan0 -b <BSSID> -vv
```

#### Sniffing (Airodump-ng)
```bash
LD_PRELOAD=/root/libnexmonkali/libnexmonkali.so airodump-ng wlan0
```

---

**Credits:**
Original work by the Nexmon Team.
Modifications for Samsung S10/Kali integration by [Your Name/Handle].
