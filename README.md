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
3. Extended Range (TX Power Boost)
To maximize signal reach for both injection and reception, this library issues an automatic WLC_SET_TXPWR command (configured to 500) upon interface initialization. This overrides default power-saving regulatory limits.

4. Channel Switching Stability (Deafness Fix)
The Problem: On some firmware versions (like the S10 BCM4375B1), switching channels—whether manually or via tools like Wifite—causes the Wi-Fi chip to reset its Power Management state to "Enabled" (Sleep Mode). This leads to the interface going "deaf" (missing beacons/packets) immediately after a channel hop, causing tools to hang waiting for targets.
The Fix: We hooked the SIOCSIWFREQ (Set Frequency) call to strictly re-enforce WLC_SET_PM = 0 (Wake) and WLC_SET_PROMISC = 1 (Promiscuous) every single time the channel changes. This ensures the radio never sleeps during multi-channel attacks or scanning.
🛠️ Build Instructions
You will need an aarch64 cross-compiler or a native build environment (such as Termux or a Kali Chroot on the device).
1. Clean & Compile
# Clean previous build artifacts
make clean

# Compile the shared library
make

2. Installation
Copy the compiled shared object to a accessible location on your device.
cp libnexmonkali.so /usr/lib/libnexmonkali.so
# Or keep it in your home directory
cp libnexmonkali.so ~/libnexmonkali.so

💻 Usage Guide
To use the optimizations, you must preload the library when running Wi-Fi related tools.
Step 1: Enable Monitor Mode
This step is critical. It initializes the interface and triggers our custom IOCTLs (Power Boost & CAM).
For Samsung S10 (Galaxy S10/S10+/S10e):
nexutil -s0x613 -i -v2

For Generic Broadcom Devices:
nexutil -m2

Step 2: Running Tools (LD_PRELOAD)
You can run tools individually by exporting the library before the command.
Example: Running Airodump-ng
LD_PRELOAD=/path/to/libnexmonkali.so airodump-ng wlan0

Example: Running Reaver
LD_PRELOAD=/path/to/libnexmonkali.so reaver -i wlan0 -b <BSSID> -vv

> Pro Tip: To avoid typing this every time, you can export it for your current session:
> export LD_PRELOAD=/path/to/libnexmonkali.so
> # Now run tools normally
> airodump-ng wlan0
> 
> 
⚠️ Disclaimer
This software is for educational purposes and authorized security auditing only. The authors are not responsible for any misuse or damage caused by this software. Ensure you comply with all local laws and regulations regarding radio transmission and network security.
🏆 Credits
 * Original Work: [Nexmon Team](https://github.com/seemoo-lab/nexmon)
 * Inspiration & Motivation: [yesimxev](https://github.com/yesimxev)
 * Original Library: [RoninNada](https://github.com/RoninNada/libnexmonkali)
 * S10 Optimization & Fork: [qazianwar222](https://github.com/pr0misc)
