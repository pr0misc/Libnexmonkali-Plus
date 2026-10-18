# Libnexmonkali-Plus 🚀

> A high-performance, universal Nexmon userspace library for Broadcom Wi-Fi chips — supporting both **AArch64** (Samsung S10/S21+, modern phones) and **ARMHF** (TicWatch Pro/Pro3, Raspberry Pi).

## 📖 Overview

This library intercepts system calls via `LD_PRELOAD` to drive monitor mode, frame injection, and channel switching on Nexmon-patched Broadcom chips. It runs on both **bcmdhd** and **brcmfmac** ports and asks the patched firmware which injection lane it implements instead of assuming the driver's name tells you — it does not: the TicWatch runs `bcmdhd`, and the Raspberry Pi ports run `brcmfmac`.

### Supported Devices

| Device | Chip | Driver | Arch | Injection Method |
|---|---|---|---|---|
| Samsung S10/S21+ | BCM4375b1 | `bcmdhd` | aarch64 | `NEX_INJECT_FRAME` IOCTL |
| TicWatch Pro/Pro3 | BCM43430 / BCM43436b0 ¹ | `bcmdhd` | armhf | Raw socket → `wl_send_hook` |
| Raspberry Pi (64-bit) | Various | `brcmfmac` | aarch64 | Raw socket → `wl_send_hook` |
| Raspberry Pi (32-bit) | Various | `brcmfmac` | armhf | Raw socket → `wl_send_hook` |

¹ The loaded `fw_bcm*.bin` (`bcm43430a1` or `bcm43436b0`) depends on the watch's silicon revision; both patches implement the same `wl_send_hook` injection gate, and the firmware probe below identifies the lane at runtime.

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
Hooks all major packet transmission syscalls: `write()`, `sendto()`, `sendmsg()`, `send()`, `sendmmsg()`. On the `NEX_INJECT_FRAME` lane (the S10/S21+ port) frames are routed through the IOCTL. On the `wl_send_hook` lane (the TicWatch and Raspberry Pi ports) they are written to a raw socket and the firmware's tx hook injects them. The lane is chosen by the firmware probe below, not by the kernel driver's name.

### 2. Automatic Injection-Lane Detection
The lane is chosen by what the **firmware patch** implements, not by the kernel driver's name — the two do not line up (the watch runs `bcmdhd` too, and the Raspberry Pi ports run `brcmfmac` on both architectures).

On **aarch64** the library keeps its original detection: it probes `/sys/module/brcmfmac/` and `/sys/module/bcmdhd/` and falls back to the IOCTL lane.

On **armhf** it asks the firmware directly at init, before any tool runs. The discriminator is command **400 `NEX_GET_CAPABILITIES`**, which is implemented *only* by the patches that inject through the firmware's tx path (`wl_send_hook`) — `bcm43430a1` / `bcm43436b0` (TicWatch) and the Raspberry Pi ports. The `bcm4375b1` patch (S10/S21) has no case for 400, so the call fails there, which makes it a discriminator in both directions:

| Firmware answers… | Lane taken |
|---|---|
| `NEX_GET_CAPABILITIES` (400) | raw socket → `wl_send_hook` |
| rejects 400, but answers `WLC_GET_MONITOR` | `NEX_INJECT_FRAME` (408) IOCTL |
| neither | raw socket, with a warning |

`NEXMON_DEBUG=1` prints the decision and the evidence it was based on:

```
LIBNEXMON: iface=wlan0 driver=bcmdhd fw=9.88.4.65 (r745790) caps=0x7 probe=0 -> inject=raw (firmware advertises NEX_CAP_FRAME_INJECTION)
```

`NEXMON_INJECT=raw|ioctl` overrides the probe if a firmware ever misanswers it.

### 3. Reliable Handshake Capture
Forces `WLC_SET_PM=0` (Constantly Awake Mode) to prevent the chip from sleeping during EAPOL handshakes. Promiscuous mode (`WLC_SET_PROMISC=1`) is enforced after every channel change. On the armhf watch lane these four stability ioctls are **off by default** — see [Stability ioctls are off by default on the watch](#stability-ioctls-are-off-by-default-on-the-watch).

### 4. Smart Speed (Auto-Optimization)
Inspects `/proc/self/comm` to detect the running tool and automatically sets the optimal injection delay. Can be overridden with the `NEXMON_DELAY` environment variable.

### 5. Channel Switching Stability
Re-enforces wake and promiscuous state after every channel change. For Kismet and hcxdumptool, periodic stability enforcement runs every 50 injected frames. On the armhf watch lane the post-hop part is disabled by default; see the TicWatch section.

### 6. Kismet & hcxdumptool Bypass
- Fakes `NL80211_CMD_SET_INTERFACE` success (prevents "can't set monitor mode" errors)
- Suppresses `EOPNOTSUPP`/`EINVAL` netlink errors on read (prevents tool abort)
- Forces `SIOCSIWMODE` success for Kismet's legacy monitor mode path — and on the watch, for every tool, where the call is also kept away from the driver entirely (see the TicWatch section)

### 7. Configurable Interface
Set `NEXMON_IFACE` environment variable to override the default `wlan0` interface name.

## ⌚ TicWatch Pro / Pro 3 (armhf)

The watch takes a different route to the radio than the S10. Two things have to be right for frames to actually leave it, and a third — a committed association — is what makes the AP answer them.

### The frames have to carry a radiotap header

The watch firmware's `wl_send_hook` picks frames off the tx path with this gate:

```c
if (wlc->monitor && p != 0 && p->data != 0 && ((short *) p->data)[0] == 0)
  return inject_frame(wl, p);
```

`((short *) p->data)[0] == 0` is the radiotap present-bitmap: a frame whose first two bytes are zero. `inject_frame()` then reads `rtap_len` from byte 2, walks the radiotap fields for `IEEE80211_RADIOTAP_RATE`, pulls the header off with `skb_pull()`, and hands the rest to `sendframe()` with that rate.

So on the raw lane a **bare 802.11 frame is not injected** — it goes out as an ordinary data frame. The library prepends a minimal 8-byte radiotap header (`it_version` 0, `it_pad` 0, `it_len` 8) to anything that does not already start with one, and leaves a frame that brings its own header alone. `write()`/`sendto()`/`send()` still report the caller's byte count, not the padded length.

A frame larger than 4096 bytes cannot be copied behind the preamble; it is passed through uncopied rather than dropped.

### Monitor mode is a precondition, and the library never re-enables it

`wl_send_hook` gates injection on `wlc->monitor`, so the firmware has to be in monitor mode *before* the tool starts. That is what `nexutil -m2` is for, run from the Android terminal first (see below).

Kismet asks for monitor mode again on startup through `NL80211_CMD_SET_INTERFACE`, and the library answers that with a fake success while touching nothing on the radio. That is deliberate, and it matters: the interface is already in monitor mode, so carrying the request out would be a **redundant re-enable, which crashes the firmware**. The same reasoning is why a request for `NL80211_IFTYPE_STATION` is ignored rather than acted on — a tool that resets the interface to managed partway through startup would otherwise tear down the monitor mode you set.

The legacy path gets the same answer for the same reason. airodump-ng, aireplay-ng and reaver ask through `SIOCSIWMODE` rather than nl80211, and on the watch that call is worse than useless: the kernel answers it by going **down into the firmware**, so the redundant re-enable happens whether or not the library agrees to it. The library therefore does not forward `SIOCSIWMODE` to the driver at all for the interface it watches, answers it from the firmware's own state, and reports success without writing anything — in either direction, so a tool resetting the interface to managed cannot tear monitor mode down either. A call for any *other* interface is forwarded untouched; that interface is not the library's business.

This does not hide a mistake. `SIOCGIFHWADDR` and `SIOCGIWMODE` report what the firmware is actually doing, so a tool that arrives before `nexutil -m2` is still told the truth there, and the `SIOCSIWMODE` line says so in as many words.

The interface-down request gets the same treatment. A `SIOCSIFFLAGS` that clears `IFF_UP` while the firmware is in monitor mode would make the netdev really go down; Android then reads `isUp=false` and tears its Wi-Fi stack down around a radio that is still armed — on Wear OS it re-initialises the dongle under the running capture, which is where the observed reboots died. The library answers success without touching the radio. The up direction, every request for another interface, and a downward request while monitor is not armed are forwarded untouched. `NEXMON_ALLOW_IFDOWN=1` forwards even the swallowed one, for a deliberate reset.

So: set monitor mode once from the Android side, then start the tool. This is the one thing on the watch the library cannot do for you, by design.

### Stability ioctls are off by default on the watch

On the S10 the library re-asserts `WLC_SET_PM`, `WLC_SET_WAKE`, `WLC_SET_SCANSUPPRESS` and `WLC_SET_PROMISC` after every channel change. On the watch those four run per hop under a channel-hopping tool, and that is exactly what took the radio down: with Kismet driving, the watch rebooted twice, the second time with `dhd` re-downloading firmware immediately before the system died (`console-ramoops`: `dhd_conf_set_path_params`, then `Fatal error on the modem`). A dongle that has to be reloaded mid-capture is the crash, not the cure.

They are not needed on this lane: airodump-ng hops channels through WEXT and never reaches that path, and it captures on the watch without them. `NEXMON_STABILITY=1` turns them back on if you want to measure the difference. "Stability ioctls" in the table below means this set.

### Committed association: making the AP answer (reaver / bully)

There is one more hardware requirement on this radio, and it is specific to tools that need the AP to answer a data frame — reaver, bully, and anything doing a WPS or EAP exchange.

The d11 ACKs a received frame only for a station the firmware holds as associated. With monitor armed and no association, an injected EAPOL START still leaves the radio, but the AP sees an unassociated class-3 frame and answers it with a deauth (reason 7, or reason 23 after an EAP timeout). Reaver retries EAPOL START and never receives the AP's EAPOL response, no matter how correct its frames are. No `LD_PRELOAD` shim can produce that ACK — it is a SIFS-time hardware job — so the association has to exist before the EAPOL frame goes out.

On the raw lane the library builds it, for `reaver` and `bully` by default (`NEXMON_ASSOC_AUTO=1` opts any tool in, `=0` opts them out). The lane watches the frames the tool injects and learns the target from them:

- an authentication request names the AP (Addr1);
- an association request names the AP and carries the SSID;
- the tool's command line (`-b`/`--bssid`, `-c`/`--channel`, `-e`/`--ssid`) fills in anything not seen yet — this is what makes `reaver -A` work;
- `NEXMON_ASSOC_BSSID`, `NEXMON_ASSOC_SSID`, `NEXMON_ASSOC_CHAN` and `NEXMON_ASSOC_FREQ` override or complete the target.

The channel the tool tuned to is recorded from `SIOCSIWFREQ` and nl80211 `SET_WIPHY`. Only 2.4 GHz channels 1–14 are eligible; a target outside that range is not joined.

When the first EAPOL frame arrives:

1. If the interface is already associated to the target BSSID (`SIOCGIWAP`), nothing is changed — the d11 is already ACKing.
2. If it is associated to a *different* AP, that link cannot carry frames for the target's channel: reaver's auth request would never leave it. The lane sends `NL80211_CMD_DISCONNECT` (reason 3) and re-tunes to the target channel, then continues. This is the one case where the lane deliberately changes an existing association, and it says so in the log.
3. It sends a driver-level `NL80211_CMD_CONNECT` for the target — no supplicant involved — with the SSID, BSSID, frequency, `AUTH_TYPE=0`, `WPA_VERSIONS=2`, the CCMP pairwise/group ciphers, the PSK AKM, HT/VHT capabilities, and the supplicant's own 43-byte IE set (extended capabilities + WPS enrollee IE + operating classes, no RSN IE). The WPS IE is what makes hostapd run EAP-WSC instead of a 4-way handshake.
4. The EAPOL frame is held until the kernel reports the connect committed (the mlme `CONNECT` event, or `EALREADY`), up to 2.5 s, then released. This closes the race between reaver's own assoc request and its EAPOL START: a frame that left before the association committed would let the AP deauth the same MAC and tear the new link down with it.
5. If the connect fails, the frame is released anyway and the attempt is retried on later EAPOL frames — up to 4 attempts, 3 s apart. If the link is later lost to a deauth, the next EAPOL frame re-establishes it.

This code path runs only when the injection lane is the raw socket; on the `NEX_INJECT_FRAME` lane the firmware already handles the association and nothing here runs. It is compiled only for armhf — the aarch64 build has none of it.

Under `NEXMON_DEBUG=1` the lane logs each decision, and the summary gains:

```
LIBNEXMON[--] association         : attempts=1 committed=1 failed=0 | EAPOL frames held for it=1
```

An example run (the AP must be WPS-enabled and in range):

```bash
nexutil -m2
LD_PRELOAD=/usr/lib/libnexmonkali.so reaver -i wlan0 -b <BSSID> -c <CH>
```

`reaver -A` (no association frames from reaver) works the same as long as the target is known: it is read from `-b`/`-c`/`-e` on the command line, or from `NEXMON_ASSOC_*`:

```bash
NEXMON_ASSOC_BSSID=<BSSID> NEXMON_ASSOC_SSID=<SSID> NEXMON_ASSOC_CHAN=<CH> \
  LD_PRELOAD=/usr/lib/libnexmonkali.so reaver -A -i wlan0 -b <BSSID> -c <CH>
```

Operational notes:

- Stop or freeze Android's own supplicant while a WPS run is active, or it may answer EAP over the same association. The library does not stop it.
- The connect takes the radio away from any other AP it was associated to (step 2). Do not run it while something else depends on that link.
- The association is driver-level and coexists with monitor mode 2; do not re-enable monitor mode.
- The library never stores or prints a WPS PIN or PSK. It only uses the BSSID/SSID/channel you aimed it at.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `NEXMON_INJECT` | probed | `raw` or `ioctl` — force an injection lane, skipping the probe |
| `NEXMON_RAW_NO_RADIOTAP` | unset | Set to send frames exactly as given, with no preamble. Only useful if your tool already builds a correct radiotap header |
| `NEXMON_DEBUG` | unset | `1` = decisions, `2` = decisions plus a line per frame |
| `NEXMON_LOG` | unset | Mirror all of the above into this file. Setting it implies `NEXMON_DEBUG=1` |
| `NEXMON_ASSOC_AUTO` | `reaver`/`bully` only | `1` = enable the committed-association lane for any tool, `0` = disable it for all |
| `NEXMON_ASSOC_BSSID` | learned from the tool | Target AP MAC (`aa:bb:cc:dd:ee:ff`) |
| `NEXMON_ASSOC_SSID` | learned from the tool | Target SSID, up to 32 bytes |
| `NEXMON_ASSOC_CHAN` | learned from the tool | Target channel, 1–14 (2.4 GHz only) |
| `NEXMON_ASSOC_FREQ` | unset | Target frequency in MHz (2400–2500); wins over `NEXMON_ASSOC_CHAN` |
| `NEXMON_STABILITY` | off | `1` = run PM/WAKE/SCANSUPPRESS/PROMISC after each channel change (see above) |
| `NEXMON_ALLOW_IFDOWN` | unset | `1` = forward `SIOCSIFFLAGS` that clears `IFF_UP` even while monitor is armed (deliberate reset) |
| `NEXMON_KMSG` | unset | `1` = also write diagnostics to `/dev/kmsg`, so pstore keeps them across a crash. Bind-mount `/dev/kmsg` into the chroot first |

### When nothing leaves the radio

A `write()` that returns the frame length while nothing appears on the air is the watch's failure mode, and from the tool's side it is silent. `NEXMON_DEBUG` answers the whole question — which lane was taken, which call sites were seen, which frames were classified as injection and why the others were not, what radiotap header each frame carried, and where the send ended up.

```bash
NEXMON_DEBUG=1 LD_PRELOAD=/usr/lib/libnexmonkali.so reaver -i wlan0 -b <BSSID> -c <CH>
```

At level 2 a line is printed per frame, so to keep the output bounded only the first 32 are shown and then every 128th. For a whole session keep it in a file instead of a terminal:

```bash
NEXMON_LOG=/tmp/nexmon.log LD_PRELOAD=/usr/lib/libnexmonkali.so airodump-ng wlan0
```

The library prints a summary when the tool exits, and the tail of it is a verdict — the one line that says which part of the chain is at fault:

```
LIBNEXMON[--] transmit calls seen : write=1204 sendto=88 send=0 sendmsg=0 sendmmsg=0
LIBNEXMON[--] classified as inject: write=1204 sendto=88 send=0 sendmsg=0 sendmmsg=0
LIBNEXMON[--] radiotap            : added=1292 already-present=0 disabled=0 oversize=0 nomem=0
LIBNEXMON[--] results             : ok=1292 failed=0 bytes=84214
LIBNEXMON[--] VERDICT: 1292 frames were handed to the kernel (1292 with a radiotap
              header). If nothing appears on the air, the frames are reaching the
              driver and wl_send_hook is declining them — which means wlc->monitor is
              clear, so set monitor mode with `nexutil -m2` first.
```

The counters are process-wide, so the summary covers the whole run even if `NEXMON_LOG` was set late. A `SIGKILL` (or a tool that calls `_exit`) skips the summary — that is what the log file is for; the per-line records are written as they happen.

One counter under-reports: `frames in:` does not see traffic libpcap receives through its packet-ring mmap, so a successful reaver run can still show `frames in: EAPOL=0`. The tool's own log is authoritative for the receive direction.

The `ioctl` line starts with `seen=`, the number of `ioctl` calls that entered the library at all. Zero there while the tool demonstrably tried to set monitor mode means the hook is not being reached — a different fault from the tool not making the call, and the line below it says so. One cause is worth knowing because it is invisible in the source: on 32-bit ARM glibc hands tools the `__ioctl_time64` spelling of `ioctl` (and `__sendmsg64` / `__sendmmsg64` of those two) rather than the plain name, so the armhf build exports both spellings of each. `tests/check_armhf_symbols.sh` asserts that after a build.

`GET_MONITOR` and `SET_MONITOR` on that line count **requests the tool made**, not radio writes made in answer — on the watch the library never writes monitor state, so a non-zero `SET_MONITOR` is the tool asking, not the library acting.

`NEXMON_DEBUG=2` is how you tell "the tool never sent anything" from "the tool sent frames the library did not recognise as injection". Each line names the call, why it was classified the way it was, where the send ended up, and what the frame and its radiotap header look like:

```
LIBNEXMON[tx] write(fd=7, 28 B) INJECT via raw socket [classified] -> handed to the kernel | mgmt/auth seq=1 to aa:bb:cc:dd:ee:ff | radiotap 8 B present=0x00000000 no RATE field | fc=b0 00
LIBNEXMON[tx] write(fd=7, 37 B) INJECT via raw socket [classified] -> handed to the kernel | mgmt/assoc-req to aa:bb:cc:dd:ee:ff | radiotap 8 B present=0x00000000 no RATE field | fc=00 00
LIBNEXMON[tx] write(fd=1, 12 B) not injection — fd is a standard stream
```

The verdict distinguishes five outcomes: no transmit call hooked at all; transmit calls seen but none classified as injection; frames injected but every send failed; frames injected bare, with no radiotap header for `wl_send_hook` to gate on; and frames handed to the kernel successfully — which points at `wlc->monitor` and therefore at `nexutil -m2`.

Setting `NEXMON_RAW_NO_RADIOTAP=1` would produce the fourth of those on purpose; the summary says so rather than leaving you to correlate it.

### Checking it on the watch

Load the library and ask it what it found:

```bash
NEXMON_DEBUG=1 LD_PRELOAD=/usr/lib/libnexmonkali.so true
```

Expect `inject=raw (firmware advertises NEX_CAP_FRAME_INJECTION)`. If it says `ioctl`, the firmware in the `fw_bcm*.bin` slot is not a `wl_send_hook` patch — check which blob your silicon revision loads.

Monitor mode is a precondition, not something the library can fake on the watch. Put the firmware in radiotap monitor mode first, then start the tool:

```bash
nexutil -m2          # or: nexutil -s0x613 -i -v2
```

Kismet and hcxdumptool ask for monitor mode over nl80211 and get a fake success without the firmware being touched, and airodump-ng, aireplay-ng and reaver take the legacy `SIOCSIWMODE` route and get the same answer — on the watch that call is never forwarded to the driver, because the driver is what takes it into the firmware. See the section above.

To confirm a frame actually leaves the radio, deauth something you control and watch for it on a second machine in monitor mode. The failure mode to look for is a `write()` that returns the frame length while nothing appears on the air — run the tool under `NEXMON_DEBUG=1` and the summary tells you which link in the chain dropped it.

With a WPS tool, the association lane announces itself before the first EAPOL frame is released:

```
LIBNEXMON[--] association: CONNECT committed — the d11 can ACK now; releasing the EAPOL frame
```

If it instead reports `the connect did not commit (...)` or the summary shows `attempts>0 committed=0`, act on the reason on the line above: a kernel-refused connect, a timeout, or a `DISCONNECT` event with its reason code. The AP must be WPS-enabled, 2.4 GHz and in range, and Android's supplicant must not be answering EAP over the same link.

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

### Tests

- `tests/check_armhf_symbols.sh [libnexmonkali-armhf.so]` — after `make armhf`, asserts that both the plain and the `__*_time64` spellings of `ioctl`, `sendmsg`, `sendmmsg`, `recvmsg` and `setsockopt` are exported and resolve to the same function. A tool on 32-bit ARM calls the renamed ones, and a hook that has only the plain name is never entered. It reads `libnexmonkali-armhf.so` by default; `make armhf` writes `libnexmonkali.so`, so copy it or pass the path explicitly.
- `tests/twp3_lane_test.c` — a host-side harness for the TicWatch lane. It compiles `nexmon.c` with `-DARCH_ARMHF` and stubs libnexio with a fake firmware, then checks the capability probe (400 answered, rejected, absent, `NEXMON_INJECT` override), the radiotap preamble and every transmit wrapper's byte layout, the diagnostics counters/log/verdict, the `SIOCSIWMODE` path, and Kismet's libnl `SET_INTERFACE` lane. Build from the repository root:

```bash
gcc -std=c99 -I. -I/usr/include/libnl3 -DARCH_ARMHF -Wall \
    -o /tmp/twp3_lane_test tests/twp3_lane_test.c -ldl -lnl-3 -lnl-genl-3
/tmp/twp3_lane_test
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
| `NEXMON_INJECT` | probed | `raw` or `ioctl` — force an injection lane (see the TicWatch section) |
| `NEXMON_RAW_NO_RADIOTAP` | unset | Never prepend the radiotap preamble on the raw lane |
| `NEXMON_DEBUG` | unset | `1` = print the lane decision and each mode change, `2` = also a line per frame (armhf builds) |
| `NEXMON_LOG` | unset | Mirror the debug output into a file; implies `NEXMON_DEBUG=1` (armhf builds) |
| `NEXMON_ASSOC_AUTO` | `reaver`/`bully` only | Enable the committed-association lane for any tool (`0` disables it; armhf raw lane) |
| `NEXMON_ASSOC_BSSID` / `_SSID` / `_CHAN` / `_FREQ` | learned from the tool | Target for the association lane (see the TicWatch section) |
| `NEXMON_STABILITY` | off | Re-enable the per-hop stability ioctls on armhf |
| `NEXMON_ALLOW_IFDOWN` | unset | Forward interface-down requests on armhf even while monitor is armed |
| `NEXMON_KMSG` | unset | Mirror diagnostics to `/dev/kmsg` on armhf |

## ⚠️ Disclaimer

This software is for educational purposes and authorized security auditing only. The authors are not responsible for any misuse or damage caused by this software. Ensure you comply with all local laws and regulations regarding radio transmission and network security.

## 🏆 Credits

- Original Work: [Nexmon Team](https://github.com/seemoo-lab/nexmon)
- Inspiration & Motivation: [yesimxev](https://github.com/yesimxev)
- Original Library: [RoninNada](https://github.com/RoninNada/libnexmonkali)
- S10 Optimization & Fork: [qazianwar222](https://github.com/pr0misc)
- TWP3 bring-up, testing & invaluable help: [apk0mix5900](https://github.com/apk0mix5900)
