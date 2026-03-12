libnexmonkali (Samsung S10 Optimized) 🚀
> A high-performance fork of libnexmonkali tailored for the Samsung S10 and compatible AArch64 Broadcom devices.
> 
📖 Overview
This repository hosts a heavily modified version of the libnexmonkali shared library. It strips away legacy device support to focus purely on providing the best possible injection, monitor mode reliability, and range performance for modern mobile penetration testing.
While the original library intercepted write() calls, this version expands syscall hooking to support a wider range of tools (including Reaver) and patches firmware behavior to prevent packet loss during critical handshakes.
⚡ Key Modifications & Features
1. Universal Packet Injection Support
Legacy versions often caused tools like Reaver or Bully to fail because they utilize different transmission system calls. This fork implements hooks for all major packet transmission syscalls:
 * write()
 * sendto() (Crucial for Reaver)
 * sendmsg()
 * send()
 * sendmmsg()
All trapped packets are automatically encapsulated and injected via the custom Broadcom NEX_INJECT_FRAME IOCTL, ensuring full compatibility with the complete Aircrack-ng suite, MDK4, and Reaver.
2. Reliable Handshake Capture (Power Management Fix)
The Problem: Standard firmware often puts the Wi-Fi chip to sleep while waiting for DTIM beacons, causing it to miss EAPOL M2/M4 packets, resulting in incomplete 4-way handshake captures.
The Fix: We inject an explicit WLC_SET_PM = 0 (Constantly Awake Mode) command during initialization. This forces the radio to stay active, ensuring 100% frame capture rate during WPA handshakes.
3. Extended Range (TX Power)
TX power behavior is firmware/device dependent. This fork focuses on monitor/injection stability and compatibility; apply TX power changes explicitly with your preferred tooling if needed.

4. Channel Switching Stability (Deafness Fix)
The Problem: On some firmware versions (like the S10 BCM4375B1), switching channels—whether manually or via tools like Wifite—causes the Wi-Fi chip to reset its Power Management state to "Enabled" (Sleep Mode). This leads to the interface going "deaf" (missing beacons/packets) immediately after a channel hop, causing tools to hang waiting for targets.
The Fix: We hooked the SIOCSIWFREQ (Set Frequency) call to strictly re-enforce WLC_SET_PM = 0 (Wake) and WLC_SET_PROMISC = 1 (Promiscuous) every single time the channel changes. This ensures the radio never sleeps during multi-channel attacks or scanning.

5. Smart Speed (Manual Control)
The library now defaults to maximum throughput with no automatic throttling:
 * `*` (Default): **0ms**
 * Optional: set `NEXMON_DELAY` (nanoseconds) when you need pacing for specific tools/chip stability.
 * Safety guard: if `NEXMON_DELAY` is unset, aggressive TX tools (`aireplay-ng`, `reaver`, `bully`) get a tiny built-in 2ms pacing to reduce firmware crash risk.

6. Kismet & hcxdumptool Compatibility
Full support for advanced capture tools:
 * **Netlink Interception**: Fakes monitor mode success to prevent EINVAL/EOPNOTSUPP errors
 * **Error Suppression**: Suppresses kernel errors for unsupported operations
 * **Radio Stability**: Enforces WLC_SET_PM=0, WLC_SET_WAKE=1, WLC_SET_SCANSUPPRESS=1 to keep radio awake
 * **Radiotap Preservation**: hcxdumptool's radiotap headers are preserved for full injection control

7. Attack Switching Stability
The library includes runtime stability enforcement (PM/WAKE/PROMISC/SCANSUPPRESS) during monitor/injection workflows to reduce "deaf" states during attack switching and channel changes.

🛠️ Build & Install
You will need an arm64 or armhf cross-compiler (or a native build environment such as Termux/NetHunter).

1. Build & Install
```bash
# Clean, Compile, and Install to /usr/bin/nxsp
make clean && make && sudo make install

# For armhf toolchains/devices
make clean && make ARCH=armhf && sudo make install
```

💻 Usage Guide
We provide a global helper script `nxsp` (Nexmon Shim Program) to make running tools easy.

Step 1: Enable Monitor Mode (Android Side)
This step initializes the hardware. Do this in a Root terminal (Termux/ADB):
```bash
nexutil -s0x613 -i -v2
```

Step 2: Run Tools (NetHunter Side)
Use `nxsp` to run tools. You have two options:

**Option A: Single Command (Recommended)**
Run explicit commands with default max throughput (or custom delay):
```bash
# Auto-detect (Best Speed)
nxsp 0 reaver -i wlan0 -b ...

# Manual Override (e.g., 15ms)
nxsp 15 mdk4 wlan0 ...
```

**Option B: Shell Mode (Legacy Style)**
Load the library into a new shell session. All subsequent commands in this shell will use the library.
```bash
# Enter "Nexmon Shell"
nxsp load

# Check if it's working
echo $LD_PRELOAD  # Should show /usr/lib/libnexmonkali.so
echo $NEXMON_DELAY # Should be 0 (default max-throughput mode)

# Run tools normally
reaver -i wlan0 ...

# Exit the shell to unload
exit
# Or force unload (starts clean shell)
nxsp unload
```

**Legacy Usage (LD_PRELOAD):**
You can still use the traditional method if you prefer:
```bash
export NEXMON_DELAY=0
LD_PRELOAD=/usr/lib/libnexmonkali.so reaver ...
``` 
> 
⚠️ Disclaimer
This software is for educational purposes and authorized security auditing only. The authors are not responsible for any misuse or damage caused by this software. Ensure you comply with all local laws and regulations regarding radio transmission and network security.
🏆 Credits
 * Original Work: [Nexmon Team](https://github.com/seemoo-lab/nexmon)
 * Inspiration & Motivation: [yesimxev](https://github.com/yesimxev)
 * Original Library: [RoninNada](https://github.com/RoninNada/libnexmonkali)
 * S10 Optimization & Fork: [qazianwar222](https://github.com/pr0misc)
