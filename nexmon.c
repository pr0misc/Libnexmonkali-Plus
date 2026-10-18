/***************************************************************************
 *                                                                         *
 *          ###########   ###########   ##########    ##########           *
 *         ############  ############  ############  ############          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ##            ##            ##   ##   ##  ##        ##          *
 *         ###########   ####  ######  ##   ##   ##  ##    ######          *
 *          ###########  ####  #       ##   ##   ##  ##    #    #          *
 *                   ##  ##    ######  ##   ##   ##  ##    #    #          *
 *                   ##  ##    #       ##   ##   ##  ##    #    #          *
 *         ############  ##### ######  ##   ##   ##  ##### ######          *
 *         ###########    ###########  ##   ##   ##   ##########           *
 *                                                                         *
 *            S E C U R E   M O B I L E   N E T W O R K I N G              *
 *                                                                         *
 * This file is part of NexMon.                                            *
 *                                                                         *
 * Based on:                                                               *
 *                                                                         *
 * This code is based on the ldpreloadhook example by Pau Oliva Fora       *
 * <pofłeslack.org> and the idea of hooking ioctls to fake a monitor mode  *
 * interface, which was presented by Omri Ildis, Yuval Ofir and Ruby       *
 * Feinstein at recon2013.                                                 *
 *                                                                         *
 * Copyright (c) 2016 NexMon Team                                          *
 *                                                                         *
 * NexMon is free software: you can redistribute it and/or modify          *
 * it under the terms of the GNU General Public License as published by    *
 * the Free Software Foundation, either version 3 of the License, or       *
 * (at your option) any later version.                                     *
 *                                                                         *
 * NexMon is distributed in the hope that it will be useful,               *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of          *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           *
 * GNU General Public License for more details.                            *
 *                                                                         *
 * You should have received a copy of the GNU General Public License       *
 * along with NexMon. If not, see <http://www.gnu.org/licenses/>.          *
 *                                                                         *
 **************************************************************************/

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <errno.h>
#include <linux/if_arp.h>
#if defined(ARCH_ARMHF)
/* Watch lane only: struct sock_fprog and BPF_CLASS, used by nex_setsockopt_body.
 * glibc only pulls in <asm/socket.h> under __USE_MISC, which this file's
 * _POSIX_C_SOURCE turns off — so the one constant needed is spelled out. It is
 * 26 on every Linux architecture, from asm-generic/socket.h. */
#include <linux/filter.h>
#ifndef SO_ATTACH_FILTER
#define SO_ATTACH_FILTER 26
#endif
/* The association lane (nex_assoc_*, near the raw transmit path) speaks
 * generic netlink through the real syscalls directly, so it can never re-enter
 * the libnl hooks this library installs. <poll.h> is how its waits are
 * bounded; <linux/netlink.h> names struct sockaddr_nl and the membership
 * option. Both are armhf-only, like everything else the watch lane adds. */
#include <linux/netlink.h>
#include <poll.h>
#endif
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <monitormode.h>
#include <net/if.h>
#include <netdb.h>
#include <nexioctls.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#define CONFIG_LIBNL

#ifdef CONFIG_LIBNL
#include <linux/genetlink.h>
#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#endif // CONFIG_LIBNL

typedef unsigned int uint;

#define TYPEDEF_BOOL // define this to make <typedefs.h> not throw an error
                     // trying to redefine bool
#include <stdint.h>
#include <typedefs.h>
typedef uint16_t uint16;
typedef uint8_t uint8;
#include <bcmwifi_channels.h>

#define WLC_GET_MONITOR 107
#define WLC_SET_MONITOR 108

struct nexio {
  int type;
  struct ifreq *ifr;
  int sock_rx_ioctl;
  int sock_rx_frame;
  int sock_tx;
  unsigned int securitycookie;
};

extern int nex_ioctl(struct nexio *nexio, int cmd, void *buf, int len,
                     bool set);
extern struct nexio *nex_init_ioctl(const char *ifname);

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *)-1l)
#endif

#define REAL_LIBC RTLD_NEXT
#ifdef CONFIG_LIBNL
#define REAL_LIBNL RTLD_NEXT
#endif // CONFIG_LIBNL

int frequency_to_channel(int);
int nex_set_channel_simple(int);
int nex_set_channel_full(uint32, uint32, uint32, uint32);

typedef int request_t;

typedef void (*sighandler_t)(int);

struct mmsghdr {
  struct msghdr msg_hdr;
  unsigned int msg_len;
};

static struct nexio *nexio = NULL;

static const char *ifname = "wlan0";

// Injection methods
#define INJECT_IOCTL       0   // bcmdhd driver (e.g., S10, S21) uses NEX_INJECT_FRAME (408)
#define INJECT_RAW_SOCKET  1   // brcmfmac driver (e.g., TicWatch, RPi) uses wl_send_hook passthrough

#if defined(ARCH_ARMHF)
// NEX_GET_CAPABILITIES is implemented only by the patches that inject through
// the firmware tx path (wl_send_hook): bcm43430a1/bcm43436b0 (TicWatch) and the
// Raspberry Pi ports. The bcm4375b1 patch (S10/S21) has no case for it, so the
// call fails there — which makes it a discriminator in both directions.
#define NEX_GET_CAPABILITIES   400
#define NEX_CAP_FRAME_INJECTION (1 << 2)
#endif

// Detected injection method. armhf starts on the raw lane because the watch
// injects through wl_send_hook, not through the ioctl the S10 uses — the
// firmware probe in nex_detect_injection_method() confirms or overrides it.
#if defined(ARCH_ARMHF)
static int current_inject_method = INJECT_RAW_SOCKET;
#else
static int current_inject_method = INJECT_IOCTL;
#endif

static int (*func_sendto)(int, const void *, size_t, int,
                          const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*func_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*func_send)(int, const void *, size_t, int) = NULL;
static int (*func_sendmmsg)(int, struct mmsghdr *, unsigned int, int) = NULL;
static int (*func_ioctl)(int, request_t, void *) = NULL;
static int (*func_socket)(int, int, int) = NULL;
static int (*func_bind)(int, const struct sockaddr *, int) = NULL;
static ssize_t (*func_write)(int, const void *, size_t) = NULL;
#ifdef CONFIG_LIBNL
static int (*func_nl_send_auto_complete)(struct nl_sock *,
                                         struct nl_msg *) = NULL;
#endif // CONFIG_LIBNL

static long inject_delay_ns = 70000000; // Default 70ms interruption delay

#if defined(ARCH_ARMHF)
// NEXMON_RAW_NO_RADIOTAP=1: never prepend the preamble on the raw lane.
static int nex_radiotap_disabled = 0;
#endif

#if defined(ARCH_ARMHF)
/* ── TicWatch diagnostics ────────────────────────────────────────────────
 *
 * Every way this library can fail on the watch is silent. A frame the firmware
 * declines to inject looks exactly like one that went out, and a transmit call
 * that never reached the injection path looks exactly like one that did — in
 * both cases the tool sees a successful write. So the watch build keeps a tally
 * of every decision it makes, and can print the reasoning behind each one.
 *
 *   NEXMON_DEBUG=1     decisions: lane probe, classification, mode changes
 *   NEXMON_DEBUG=2     the above, plus a line per frame. The first 32 are
 *                      printed, then every 128th, so a long run stays legible
 *   NEXMON_LOG=<path>  mirror all of the above into a file, so the record
 *                      survives the tool closing or redirecting stderr.
 *                      Setting it alone implies NEXMON_DEBUG=1
 *
 * A tally and a verdict are printed when the process exits, at any level.
 *
 * None of this is compiled into the aarch64 build — the S10 lane keeps its
 * own code path, byte for byte.
 *
 * Log lines go out through the real write(2), fetched below, so that a line
 * of diagnostics can never be mistaken for a frame by the hook further down.
 */
#include <fcntl.h>   /* open(), for NEXMON_LOG */
#include <unistd.h>  /* getpid(), to name the process a banner came from */

static int nex_dbg = 0;          /* 0 = quiet, 1 = decisions, 2 = per frame */
static int nex_log_fd = -1;
static ssize_t (*nex_real_write)(int, const void *, size_t) = NULL;

#define NEX_LOG_FIRST 32
#define NEX_LOG_EVERY 128

/* Plain file and stream writes outnumber frames by orders of magnitude in a
 * tool that logs to disk — airodump-ng writes its .cap once per captured
 * packet, none of which is injection. They get a budget of their own rather
 * than sharing the frame one, so a passive tool's disk writes cannot crowd out
 * the frame lines that actually matter. */
#define NEX_PASS_FIRST 8
#define NEX_PASS_EVERY 1024

/* A macro, not a function, so it can name socket_to_type from the hooks below
 * without forward-declaring the array up here. */
#define NEX_FD_IS_RAW_SOCKET(fd)                                               \
  ((fd) > 2 &&                                                                 \
   (fd) < (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&         \
   socket_to_type[(fd)] == SOCK_RAW)

static unsigned long nex_seen_write, nex_seen_sendto, nex_seen_send,
                     nex_seen_sendmsg, nex_seen_sendmmsg;
static unsigned long nex_inj_write, nex_inj_sendto, nex_inj_send,
                     nex_inj_sendmsg, nex_inj_sendmmsg;
/* How many of the calls above were on an fd that is not a tracked raw socket,
 * i.e. a file or a stream. Tells a passive tool apart from a misconfigured one. */
static unsigned long nex_seen_nonsock;
static unsigned long nex_rtap_added, nex_rtap_kept, nex_rtap_off,
                     nex_rtap_oversize, nex_rtap_nomem;
static unsigned long nex_tx_ok, nex_tx_fail, nex_tx_bytes;
static unsigned long nex_sock_raw, nex_sock_other, nex_bind_match, nex_bind_other;
static unsigned long nex_mon_get, nex_mon_set, nex_chan_set, nex_devpriv;
/* Interface-down requests answered success without reaching the driver, and
 * the firmware monitor value that decided it — see the pre-call gate in
 * ioctl(). A real down while monitor is armed is what took Android's Wi-Fi
 * stack down, and its auto-restart is what re-initialised the dongle under the
 * session; this counter is how a run says the gate fired. */
static unsigned long nex_ifdown_fake;
static int nex_ifdown_swallow, nex_ifdown_mon;
/* Every ioctl() that entered the hook at all, whatever the request. If this is
 * zero the hook is dead and every counter below it is meaningless — which is
 * not the same thing as the tool not making the call. */
static unsigned long nex_ioctl_seen;
static unsigned long nex_nl_faked, nex_nl_chan, nex_nl_suppressed,
    nex_nl_iftype;
/* Faked sends whose nl_wait_for_ack() was answered locally. A faked send that
 * is never waited for, and a wait that was answered for the wrong reason, look
 * identical from outside — these two are printed side by side. */
static unsigned long nex_nl_waited;
/* Netlink receives, split by which hook saw them. libnl tools arrive through
 * recvmsg(); a tool that arrives through read() is one whose receive path the
 * older suppression hook can still reach. */
static unsigned long nex_rx_netlink, nex_rx_other, nex_rx_msg_netlink;
static unsigned long nex_frames;

/* The committed-association lane (nex_assoc_*, next to the raw transmit path).
 * These are what a run says when the question is "did the shim actually make
 * the radio associate before the EAPOL START went out": how many times it
 * issued CONNECT, how many committed, how many failed, and how many transmit
 * calls were held back waiting for one. */
static unsigned long nex_assoc_kick_n, nex_assoc_ok_n, nex_assoc_fail_n,
                     nex_assoc_gate_n;
static void nex_assoc_note_channel(int channel);

/* BPF programs a tool attached to a socket it will receive on, e.g. reaver's
 * `wlan type mgt or wlan type data`. A drop-everything program means every
 * frame the kernel delivers on that socket is discarded before the tool can see
 * it — which looks exactly like a silent radio. Recorded from the
 * setsockopt() hook so the two can be told apart. */
#define NEX_FILTERS 8
static struct {
  int fd;
  int pass;                        /* 0 = drops everything, 1 = passes something */
} nex_filter_seen[NEX_FILTERS];
static unsigned nex_filter_n;

/* What the radiotap decision did, set in nex_raw_tx_iov() and reported in the
 * per-frame line. The reporting helpers live below nex_framef(). */
static const char *nex_last_note = "(none)";

/* ── What each frame is, and when it moved ───────────────────────────────
 *
 * A byte count cannot answer the question these logs exist for. "46 B sent"
 * could be an EAPOL START, a null frame or a fragment, and in the tool's own
 * output "the AP never answered" is indistinguishable from "the frame never
 * left". So every frame that crosses the injection lane is named from its own
 * control word, and the frames that carry an authentication exchange are
 * called out whether or not per-frame logging is on.
 *
 * The split matters for cost: classing a frame reads a handful of bytes and
 * formats nothing, so it can run on every frame a capture delivers; naming
 * one costs an snprintf and runs only for frames that will be printed.
 */
enum { NEX_F_UNKNOWN = 0, NEX_F_CTRL, NEX_F_MGMT, NEX_F_DATA, NEX_F_EAPOL };

/* Which of the three receive calls delivered a frame. A silent receive log is
 * ambiguous between "nothing arrived" and "it arrived through a call this
 * library does not hook" unless these are counted and printed. */
#define NEX_HOOK_READ 0
#define NEX_HOOK_RECVFROM 1
#define NEX_HOOK_RECVMSG 2

/* Milliseconds since this library loaded, so a line here can be lined up
 * against the tool's own output and against a capture taken on another radio. */
static struct timespec nex_t0 = {0, 0};
static long nex_ms_since(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
    return 0;
  if (nex_t0.tv_sec == 0 && nex_t0.tv_nsec == 0)
    nex_t0 = now;
  return (long)(now.tv_sec - nex_t0.tv_sec) * 1000 +
         (long)(now.tv_nsec - nex_t0.tv_nsec) / 1000000;
}

static char nex_last_frame[176];
static unsigned nex_last_class;

/* The errno of the last failed transmit, captured in the wrapper that made the
 * call itself: by the time the per-frame line is printed a rate-limit sleep has
 * run in between, and a nap that returns early would leave its own errno in the
 * way of the one that matters. */
static int nex_last_errno;

/* Injected sizes, as a short list rather than a histogram: the tools send a
 * few distinct sizes and the summary is read by a person. */
#define NEX_SIZES 10
static unsigned nex_size_val[NEX_SIZES];
static unsigned long nex_size_n[NEX_SIZES];
static unsigned nex_size_used, nex_size_more;

/* Frames by what they are. These are the counters that answer "did the EAPOL
 * START go out, and did anything come back" — which no byte counter can. */
static unsigned long nex_tx_mgmt_n, nex_tx_data_n, nex_tx_eapol_n, nex_tx_unk_n;
static unsigned long nex_rx_mgmt_n, nex_rx_data_n, nex_rx_eapol_n, nex_rx_unk_n;
static unsigned long nex_rx_total, nex_rx_deauth_n, nex_rx_frames;
static unsigned long nex_rx_hook_read, nex_rx_hook_recvfrom, nex_rx_hook_recvmsg;
static unsigned long nex_rx_announced, nex_rx_first;

static void nex_size_add(unsigned len) {
  unsigned i;
  for (i = 0; i < nex_size_used; i++)
    if (nex_size_val[i] == len) {
      nex_size_n[i]++;
      return;
    }
  if (nex_size_used < NEX_SIZES) {
    nex_size_val[nex_size_used] = len;
    nex_size_n[nex_size_used] = 1;
    nex_size_used++;
  } else {
    nex_size_more++;
  }
}

static unsigned nex_le16(const unsigned char *p) {
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

/* Step over a radiotap header if there is one. Both directions carry one on
 * this lane, but a frame that lost it is exactly the frame wl_send_hook drops,
 * so this reports what it found rather than assuming. */
static const unsigned char *nex_80211(const unsigned char *b, size_t len,
                                      size_t *out_len, size_t *rtap_len) {
  *rtap_len = 0;
  *out_len = len;
  if (len >= 8 && b[0] == 0 && b[1] == 0 && b[2] >= 8 && b[2] <= len) {
    *rtap_len = b[2];
    *out_len = len - b[2];
    return b + b[2];
  }
  return b;
}

/* Offset of the radiotap RATE byte, or -1 when the header carries none. Only
 * TSFT and FLAGS can precede RATE among the low fields and only TSFT changes
 * the alignment, so this walks those three and stops. The rate a frame is sent
 * at is chosen by the firmware from this field, so "no RATE field" is a fact
 * worth having in the log rather than an inference from the frame's size. */
static int nex_rtap_rate_off(const unsigned char *r, size_t len) {
  unsigned present;
  size_t off = 8;
  if (len < 8 || r[0] != 0)
    return -1;
  present = (unsigned)r[4] | ((unsigned)r[5] << 8) | ((unsigned)r[6] << 16) |
            ((unsigned)r[7] << 24);
  if (present & (1u << 0)) {          /* TSFT: 8 bytes, 8-aligned */
    off = (off + 7) & ~(size_t)7;
    off += 8;
  }
  if (present & (1u << 1))            /* FLAGS: 1 byte */
    off += 1;
  if (present & (1u << 2))            /* RATE: the one wanted */
    return off < len ? (int)off : -1;
  return -1;
}

/* Length of the MAC header: 24, plus Addr4 when both DS bits are set, plus the
 * QoS control field. Needed to find where a data frame's payload begins. */
static size_t nex_hdr_len(const unsigned char *f, size_t flen) {
  size_t h = 24;
  unsigned st;
  if (flen < 24)
    return flen;
  st = (f[0] >> 4) & 0xf;
  if ((f[1] & 0x3) == 0x3)
    h += 6;
  if (st & 0x8)
    h += 2;
  return h > flen ? flen : h;
}

/* Class only — no formatting, safe to run on every frame a busy capture
 * delivers. EAPOL is the interesting one: it is the WPS exchange itself. */
static unsigned nex_frame_class(const unsigned char *f, size_t flen) {
  unsigned type, st;
  size_t h;
  if (flen < 2)
    return NEX_F_UNKNOWN;
  type = (f[0] >> 2) & 0x3;
  st = (f[0] >> 4) & 0xf;
  if (type == 1)
    return NEX_F_CTRL;
  if (type == 0)
    return NEX_F_MGMT;
  if (type != 2)
    return NEX_F_UNKNOWN;
  if (st & 0x4)                       /* null / QoS-null: no payload at all */
    return NEX_F_DATA;
  h = nex_hdr_len(f, flen);
  if (flen >= h + 8 && f[h] == 0xaa && f[h + 1] == 0xaa && f[h + 2] == 0x03 &&
      f[h + 6] == 0x88 && f[h + 7] == 0x8e)
    return NEX_F_EAPOL;
  return NEX_F_DATA;
}

static void nex_mac(char *out, size_t outsz, const unsigned char *a) {
  snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
           a[4], a[5]);
}

/* The other end of the frame: for a frame going out that is who it is
 * addressed to (Addr1), for one arriving it is who sent it (Addr2). */
static void nex_frame_peer(const unsigned char *f, size_t flen, int rx,
                           char *out, size_t outsz) {
  out[0] = 0;
  if (flen < 24)
    return;
  if (((f[0] >> 2) & 0x3) != 0 && ((f[0] >> 2) & 0x3) != 2)
    return;                           /* control frames carry only Addr1 */
  nex_mac(out, outsz, f + (rx ? 10 : 4));
}

/* Name a frame from its control word, closely enough to line this log up
 * against the tool's own. Status and reason codes are here because "the AP
 * refused" and "the AP never spoke" are different answers. */
static void nex_frame_name(const unsigned char *f, size_t flen, char *out,
                           size_t outsz) {
  unsigned type, st;
  char extra[40];
  const char *n = "mgmt";
  extra[0] = 0;

  if (flen < 2) {
    snprintf(out, outsz, "runt (%zu B)", flen);
    return;
  }
  type = (f[0] >> 2) & 0x3;
  st = (f[0] >> 4) & 0xf;

  if (type == 0) {
    switch (st) {
      case 0: n = "assoc-req"; break;
      case 1:
        n = "assoc-resp";
        if (flen >= 28)
          snprintf(extra, sizeof(extra), " status=%u", nex_le16(f + 26));
        break;
      case 2: n = "reassoc-req"; break;
      case 3:
        n = "reassoc-resp";
        if (flen >= 28)
          snprintf(extra, sizeof(extra), " status=%u", nex_le16(f + 26));
        break;
      case 4: n = "probe-req"; break;
      case 5: n = "probe-resp"; break;
      case 8: n = "beacon"; break;
      case 9: n = "atim"; break;
      case 10:
        n = "disassoc";
        if (flen >= 26)
          snprintf(extra, sizeof(extra), " reason=%u", nex_le16(f + 24));
        break;
      case 11:
        n = "auth";
        if (flen >= 28)
          snprintf(extra, sizeof(extra), " seq=%u%s", nex_le16(f + 26),
                   nex_le16(f + 26) == 2 ? " RESP" : "");
        break;
      case 12:
        n = "deauth";
        if (flen >= 26)
          snprintf(extra, sizeof(extra), " reason=%u", nex_le16(f + 24));
        break;
      case 13: n = "action"; break;
      default: break;
    }
    snprintf(out, outsz, "mgmt/%s%s", n, extra);
    return;
  }

  if (type == 1) {
    switch (st) {
      case 8: n = "ack"; break;
      case 9: n = "cts"; break;
      case 10: n = "ps-poll"; break;
      case 11: n = "rts"; break;
      case 12: n = "blockack-req"; break;
      case 13: n = "blockack"; break;
      default: n = "ctrl"; break;
    }
    snprintf(out, outsz, "ctrl/%s", n);
    return;
  }

  {  /* data: the LLC/SNAP ethertype says whether this is the WPS exchange */
    size_t h = nex_hdr_len(f, flen);
    unsigned et = 0;
    if (st & 0x4) {
      snprintf(out, outsz, "data/null");
      return;
    }
    if (flen >= h + 8 && f[h] == 0xaa && f[h + 1] == 0xaa && f[h + 2] == 0x03)
      et = ((unsigned)f[h + 6] << 8) | f[h + 7];
    if (et == 0x888e) {
      unsigned etype = flen >= h + 10 ? f[h + 9] : 0;   /* EAPOL packet type */
      if (etype == 1) { snprintf(out, outsz, "data/EAPOL-START"); return; }
      if (etype == 3) { snprintf(out, outsz, "data/EAPOL-KEY"); return; }
      if (etype == 2) { snprintf(out, outsz, "data/EAPOL-LOGOFF"); return; }
      if (etype == 0) {                                 /* an EAP packet */
        unsigned eap = flen >= h + 13 ? f[h + 12] : 0;
        const char *w = eap == 1 ? "EAP-Request"
                        : eap == 2 ? "EAP-Response"
                        : eap == 3 ? "EAP-Success"
                        : eap == 4 ? "EAP-Failure" : "EAP";
        /* EAP type follows code(1) + id(1) + length(2), so h+16 — h+13 is the
         * identifier, which is a sequence number, not the type. Both the AP's
         * request and our own response carry type 1 (Identity), and that pair
         * is the whole of the WPS conversation before the M1 message. */
        if ((eap == 1 || eap == 2) && flen >= h + 17 && f[h + 16] == 1)
          snprintf(out, outsz, "data/EAPOL-%s/Identity", w);
        else
          snprintf(out, outsz, "data/EAPOL-%s", w);
        return;
      }
      snprintf(out, outsz, "data/EAPOL-type%u", etype);
      return;
    }
    if (et == 0x0800)      snprintf(out, outsz, "data/IPv4");
    else if (et == 0x0806) snprintf(out, outsz, "data/ARP");
    else if (et == 0x86dd) snprintf(out, outsz, "data/IPv6");
    else                   snprintf(out, outsz, "data");
  }
}

/* The committed-association lane watches the frames the tool injects: the
 * auth/assoc exchange names the target, and the first EAPOL frame is held
 * until the driver has associated to it. Defined next to the raw transmit
 * path; declared here because every injected frame passes through
 * nex_note_frame(). */
static void nex_assoc_observe_tx(const unsigned char *f, size_t flen);

/* Describe a frame about to be injected, for nex_tx_result() to print. */
static void nex_note_frame(const void *buf, size_t len) {
  const unsigned char *b = (const unsigned char *)buf;
  const unsigned char *f;
  size_t flen, rtap;
  char name[64], peer[24], rt[80];
  int ro;

  nex_last_frame[0] = 0;
  nex_last_class = NEX_F_UNKNOWN;
  if (!b || len == 0)
    return;

  f = nex_80211(b, len, &flen, &rtap);
  /* Before the frame is described (and therefore before it is sent): a frame
   * that names the target starts the association, and an EAPOL frame waits for
   * one that is committed. This is the whole point of the lane — with monitor
   * armed and no association, the radio never ACKs, so the AP treats every
   * EAPOL START as a class-3 frame from a non-associated station. */
  nex_assoc_observe_tx(f, flen);
  nex_last_class = nex_frame_class(f, flen);
  nex_frame_name(f, flen, name, sizeof(name));
  nex_frame_peer(f, flen, 0, peer, sizeof(peer));

  if (rtap) {
    ro = nex_rtap_rate_off(b, rtap);
    if (ro >= 0)
      snprintf(rt, sizeof(rt), "radiotap %zu B present=0x%02x%02x%02x%02x rate=%u",
               rtap, b[7], b[6], b[5], b[4], b[ro]);
    else
      snprintf(rt, sizeof(rt),
               "radiotap %zu B present=0x%02x%02x%02x%02x no RATE field",
               rtap, b[7], b[6], b[5], b[4]);
  } else {
    snprintf(rt, sizeof(rt), "NO radiotap — wl_send_hook drops bare frames");
  }

  snprintf(nex_last_frame, sizeof(nex_last_frame), "%s%s%s | %s | fc=%02x %02x",
           name, peer[0] ? " to " : "", peer, rt, f[0], flen > 1 ? f[1] : 0);
}

/* A second home for the same lines, off unless NEXMON_KMSG=1: the kernel log.
 *
 * A run that ends in a reboot takes the file log with it — the watch has done
 * that three times now, and each time the report came back as NULs, because
 * /data had not flushed. The kernel log is the one place that survives: pstore
 * keeps it across the reset, so /sys/fs/pstore/console-ramoops after the crash
 * holds this library's last words interleaved with the driver's. That pairing
 * is the whole point — the line before dhd starts re-downloading firmware is
 * the operation that caused it.
 *
 * The chroot has no /dev/kmsg of its own; it is bind-mounted in from Android
 * before the run (`mount -o bind /dev/kmsg .../kali-armhf/dev/kmsg`). */
static int nex_kmsg_fd = -1;

static void nex_wr(const char *b, size_t n) {
  if (!nex_real_write)
    return;
  if (nex_log_fd >= 0) {
    nex_real_write(nex_log_fd, b, n);
#if defined(ARCH_ARMHF)
    /* Push it down to the disk before anything else can happen.
     *
     * A write() only reaches the page cache, and the watch has twice taken the
     * page cache with it when it went down mid-run — the reports came back as
     * NULs. A reboot that syncs first would keep the file for free, but that is
     * not a property worth betting the evidence on, and the alternative to
     * betting is not knowing which of five operations killed the radio. So at
     * NEXMON_DEBUG=1, where the log is the whole reason the run exists, every
     * line is flushed as it is written. The cost is one fsync per line, and the
     * lines are decisions, not frames. */
    if (nex_dbg >= 1)
      fsync(nex_log_fd);
#endif
  }
  if (nex_dbg >= 1)
    nex_real_write(2, b, n);
  if (nex_kmsg_fd >= 0)
    nex_real_write(nex_kmsg_fd, b, n);
}

static void nex_msg(const char *lvl, const char *fmt, va_list ap) {
  char line[512];
  long ms = nex_ms_since();
  int n = snprintf(line, sizeof(line), "[%4ld.%03ld] LIBNEXMON[%s] ", ms / 1000,
                   ms % 1000, lvl);
  if (n < 0 || n >= (int)sizeof(line))
    return;
  int m = vsnprintf(line + n, sizeof(line) - n, fmt, ap);
  if (m < 0)
    return;
  n += m;
  if (n > (int)sizeof(line) - 2)
    n = (int)sizeof(line) - 2;
  line[n++] = '\n';
  nex_wr(line, (size_t)n);
}

/* Always emitted once logging is on at any level — used for the summary and
 * for anything the operator must see regardless of verbosity. */
static void nex_logf(const char *fmt, ...) {
  va_list ap;
  if (nex_dbg < 1 && nex_log_fd < 0)
    return;
  va_start(ap, fmt);
  nex_msg("--", fmt, ap);
  va_end(ap);
}

/* Decisions. Visible at NEXMON_DEBUG=1. */
static void nex_dbgf(const char *fmt, ...) {
  va_list ap;
  if (nex_dbg < 1)
    return;
  va_start(ap, fmt);
  nex_msg("--", fmt, ap);
  va_end(ap);
}

/* True for the frames that should get a line of their own at level 2. Counting
 * happens here so that it stays correct at every level. */
static int nex_frame_worthy(void) {
  nex_frames++;
  if (nex_dbg < 2)
    return 0;
  return (nex_frames <= NEX_LOG_FIRST) || (nex_frames % NEX_LOG_EVERY) == 0;
}

static void nex_framef(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  nex_msg("tx", fmt, ap);
  va_end(ap);
}

/* The per-frame line for the receive direction, tagged so that a merged log
 * still reads as a conversation. */
static void nex_rxf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  nex_msg("rx", fmt, ap);
  va_end(ap);
}

/* One line per injected frame, plus the running result tally. */
static void nex_tx_result(const char *fn, int fd, size_t len, ssize_t ret,
                          const char *how) {
  if (ret > 0) {
    nex_tx_ok++;
    nex_tx_bytes += (unsigned long)len;
  } else {
    nex_tx_fail++;
  }
  /* Counted whether or not the line is printed: the tally is the part that has
   * to survive a long run at level 1. */
  switch (nex_last_class) {
    case NEX_F_MGMT: nex_tx_mgmt_n++; break;
    case NEX_F_DATA: nex_tx_data_n++; break;
    case NEX_F_EAPOL: nex_tx_eapol_n++; break;
    default: nex_tx_unk_n++; break;
  }
  nex_size_add((unsigned)len);

  if (ret > 0 && !nex_frame_worthy())
    return;
  nex_framef("%s(fd=%d, %zu B) INJECT via %s [%s] -> %s | %s", fn, fd, len,
             current_inject_method == INJECT_RAW_SOCKET
                 ? "raw socket"
                 : "NEX_INJECT_FRAME ioctl",
             how ? how : "classified",
             ret > 0 ? "handed to the kernel"
                     : (ret < 0 ? "FAILED" : "short write"),
             nex_last_frame[0] ? nex_last_frame : nex_last_note);
  if (ret <= 0)
    nex_framef("  ^ that send returned %zd, errno=%d (%s) — the frame did not "
               "leave this process", ret, nex_last_errno,
               nex_last_errno ? strerror(nex_last_errno) : "no error recorded");
}

/* A transmit call that was not injection. The first few are worth seeing even
 * at level 1 — they show which socket the tool is really writing to, which is
 * the whole question when nothing is being injected. */
static void nex_tx_passthru(const char *fn, int fd, size_t len, const char *why) {
  static unsigned long shown = 0;
  if (nex_dbg < 1)
    return;
  shown++;
  if (shown > NEX_PASS_FIRST && (nex_dbg < 2 || (shown % NEX_PASS_EVERY) != 0))
    return;
  if (nex_dbg < 2)
    nex_dbgf("%s(fd=%d, %zu B) not injection — %s", fn, fd, len, why);
  else
    nex_framef("%s(fd=%d, %zu B) not injection — %s", fn, fd, len, why);
}

static unsigned long nex_total_inject(void) {
  return nex_inj_write + nex_inj_sendto + nex_inj_send + nex_inj_sendmsg +
         nex_inj_sendmmsg;
}

static unsigned long nex_total_seen(void) {
  return nex_seen_write + nex_seen_sendto + nex_seen_send + nex_seen_sendmsg +
         nex_seen_sendmmsg;
}

/* The point of the whole exercise: say which of the silent failures happened,
 * rather than leaving it to be inferred from counters. */
static void nex_dump_summary(void) {
  if (nex_dbg < 1 && nex_log_fd < 0)
    return;

  nex_logf("── summary (pid %ld) ────────────────────────────────────",
           (long)getpid());
  nex_logf("transmit calls seen : write=%lu sendto=%lu send=%lu sendmsg=%lu sendmmsg=%lu",
           nex_seen_write, nex_seen_sendto, nex_seen_send,
           nex_seen_sendmsg, nex_seen_sendmmsg);
  if (nex_seen_nonsock)
    nex_logf("  of those          : %lu were not on a raw socket (file or stream "
             "writes — not injection candidates, however many there are)",
             nex_seen_nonsock);
  nex_logf("classified as inject: write=%lu sendto=%lu send=%lu sendmsg=%lu sendmmsg=%lu",
           nex_inj_write, nex_inj_sendto, nex_inj_send,
           nex_inj_sendmsg, nex_inj_sendmmsg);
  nex_logf("radiotap            : added=%lu already-present=%lu disabled=%lu oversize=%lu nomem=%lu",
           nex_rtap_added, nex_rtap_kept, nex_rtap_off, nex_rtap_oversize,
           nex_rtap_nomem);
  nex_logf("results             : ok=%lu failed=%lu bytes=%lu",
           nex_tx_ok, nex_tx_fail, nex_tx_bytes);
  nex_logf("frames out          : mgmt=%lu data=%lu EAPOL=%lu other=%lu",
           nex_tx_mgmt_n, nex_tx_data_n, nex_tx_eapol_n, nex_tx_unk_n);
  nex_logf("frames in           : mgmt=%lu data=%lu EAPOL=%lu other=%lu | deauth/disassoc=%lu",
           nex_rx_mgmt_n, nex_rx_data_n, nex_rx_eapol_n, nex_rx_unk_n,
           nex_rx_deauth_n);
  nex_logf("association         : attempts=%lu committed=%lu failed=%lu | EAPOL frames held for it=%lu",
           nex_assoc_kick_n, nex_assoc_ok_n, nex_assoc_fail_n, nex_assoc_gate_n);
  if (nex_assoc_kick_n > 0 && nex_assoc_ok_n == 0)
    nex_logf("  ^ every committed-association attempt failed. Until one succeeds "
             "the d11 never ACKs the AP and an injected EAPOL START is answered "
             "with a deauth — see the lines above this summary for the reason "
             "the driver gave.");
  if (nex_size_used || nex_size_more) {
    char sizes[240];
    size_t off = 0;
    unsigned i;
    sizes[0] = 0;
    for (i = 0; i < nex_size_used && off < sizeof(sizes) - 24; i++)
      off += (size_t)snprintf(sizes + off, sizeof(sizes) - off, "%s%uB x%lu",
                              i ? "  " : "", nex_size_val[i], nex_size_n[i]);
    if (nex_size_more)
      snprintf(sizes + off, sizeof(sizes) - off, "%s%u further size(s)",
               off ? "  " : "", nex_size_more);
    nex_logf("injected sizes      : %s", sizes);
  }
  nex_logf("receive             : read=%lu recvfrom=%lu recvmsg=%lu lifted=%lu frames",
           nex_rx_hook_read, nex_rx_hook_recvfrom, nex_rx_hook_recvmsg,
           nex_rx_total);
  if (nex_filter_n) {
    char f[200];
    size_t off = 0;
    unsigned i;
    f[0] = 0;
    for (i = 0; i < nex_filter_n && off < sizeof(f) - 32; i++)
      off += (size_t)snprintf(f + off, sizeof(f) - off, "%sfd=%d:%s",
                              i ? "  " : "", nex_filter_seen[i].fd,
                              nex_filter_seen[i].pass ? "passes-some"
                                                      : "DROPS-EVERYTHING");
    nex_logf("BPF filters         : %s", f);
    for (i = 0; i < nex_filter_n; i++)
      if (!nex_filter_seen[i].pass)
        nex_logf("  ^ a filter that drops everything is attached to fd=%d. The "
                 "radio can be delivering frames perfectly and this process will "
                 "still see nothing — that is decided in the kernel, above this "
                 "library. Re-run with NEXMON_NO_FILTER=1 to compare.",
                 nex_filter_seen[i].fd);
  }
  if (nex_rx_total == 0 && nex_bind_match > 0)
    nex_logf("  ^ a raw socket was bound to %s but not one frame came up through any "
             "of the three receive calls. Either the tool receives frames somewhere "
             "else entirely, or the radio delivered nothing while this process ran.",
             ifname);
  nex_logf("sockets             : raw=%lu other=%lu | binds matched=%lu other=%lu",
           nex_sock_raw, nex_sock_other, nex_bind_match, nex_bind_other);
  nex_logf("ioctl               : seen=%lu | GET_MONITOR=%lu SET_MONITOR=%lu chanspec=%lu SIOCDEVPRIVATE=%lu",
           nex_ioctl_seen, nex_mon_get, nex_mon_set, nex_chan_set, nex_devpriv);
  nex_logf("  ^ GET_MONITOR and SET_MONITOR count requests the tool made, not radio "
           "writes made in answer. On this lane monitor mode is a precondition set "
           "from Android and the library never writes it, so a non-zero SET_MONITOR "
           "with frames still not leaving means the tool asked and the firmware was "
           "never in monitor mode to begin with.");
  if (nex_ioctl_seen == 0)
    nex_logf("  ^ no ioctl reached this library at all — the ioctl() hook is not "
             "being entered, so the four counters after `seen` say nothing.");
  if (nex_ifdown_fake > 0)
    nex_logf("  ^ %lu interface-down request(s) were answered success without "
             "reaching the driver: the tool wanted the interface down before "
             "setting monitor mode, the radio was already armed, and a real down "
             "would have taken Android's Wi-Fi stack — and the dongle re-init its "
             "auto-restart causes — down with it.", nex_ifdown_fake);
  nex_logf("netlink             : SET_INTERFACE faked=%lu (wait answered=%lu) SET_WIPHY chan=%lu errors suppressed=%lu iftype corrected=%lu",
           nex_nl_faked, nex_nl_waited, nex_nl_chan, nex_nl_suppressed,
           nex_nl_iftype);
  if (nex_nl_iftype > 0)
    nex_logf("  ^ %lu GET_INTERFACE repl(y/ies) said STATION while the firmware was "
             "in monitor mode, and were answered MONITOR. A tool that reads the "
             "kernel's answer would otherwise take the radio down and back up to "
             "make a monitor interface of its own.", nex_nl_iftype);
  nex_logf("netlink receives    : recvmsg()=%lu | read() netlink=%lu other=%lu",
           nex_rx_msg_netlink, nex_rx_netlink, nex_rx_other);
  if (nex_nl_faked > nex_nl_waited)
    nex_logf("  ^ %lu faked SET_INTERFACE request(s) were never waited for. Harmless "
             "in itself, but it means the tool sent something else on that socket "
             "first, so the next failure it reports is a real one.",
             nex_nl_faked - nex_nl_waited);
  if (nex_rx_msg_netlink == 0 && nex_nl_faked > 0)
    nex_logf("  ^ a netlink request was faked but nothing was ever received on a "
             "netlink socket — a libnl tool that hangs here is waiting for an ACK "
             "on a path this library does not see.");

  if (nex_total_seen() == 0) {
    nex_logf("VERDICT: no transmit call was hooked at all. The tool is using a "
             "path this library does not cover (or never transmitted).");
  } else if (nex_total_inject() == 0) {
    if (nex_bind_match > 0) {
      nex_logf("VERDICT: this tool is passive — it bound a raw socket to %s and "
               "never transmitted on it. All %lu transmit calls seen were file or "
               "stream writes. Capture is unaffected by this library; the injection "
               "counters stay at zero until a tool that actually sends frames is run.",
               ifname, nex_seen_nonsock);
    } else {
      nex_logf("VERDICT: %lu transmit calls were seen, none classified as injection, "
               "and no raw socket was ever bound to %s. Either the tool writes to an "
               "interface this library is not watching (NEXMON_IFACE overrides the "
               "name) or it is not using a raw socket at all.",
               nex_total_seen(), ifname);
    }
  } else if (nex_tx_ok == 0) {
    nex_logf("VERDICT: %lu frames reached the injection path but every send failed. "
             "The radio or the socket is refusing them.", nex_total_inject());
  } else if (nex_tx_eapol_n > 0 && nex_rx_eapol_n == 0) {
    nex_logf("VERDICT: %lu EAPOL frame(s) went out and not one came back, out of %lu "
             "frame(s) received in total. The exchange is dying at the radio: either "
             "the AP never answered, or it answered and the firmware did not hand the "
             "answer up. The firmware's own view is the tiebreaker — after "
             "`echo 10 > /sys/module/bcmdhd/parameters/dhd_console_ms`, "
             "`dmesg | grep CONSOLE` prints sendframe's drop message when an injected "
             "frame was thrown away instead of transmitted.",
             nex_tx_eapol_n, nex_rx_total);
  } else if (nex_rx_eapol_n > 0) {
    nex_logf("VERDICT: the AP answered with %lu EAPOL frame(s) — the exchange is alive "
             "at the radio, so anything the tool still reports as silence is happening "
             "above this library.", nex_rx_eapol_n);
  } else if (nex_rtap_added + nex_rtap_kept == 0) {
    nex_logf("VERDICT: %lu frames injected bare — with no radiotap header the "
             "firmware's wl_send_hook gate will NOT pick them up.", nex_tx_ok);
  } else {
    nex_logf("VERDICT: %lu frames were handed to the kernel (%lu with a radiotap "
             "header). If nothing appears on the air, the frames are reaching the "
             "driver and wl_send_hook is declining them — which means wlc->monitor "
             "is clear, so set monitor mode with `nexutil -m2` first.",
             nex_tx_ok, nex_rtap_added + nex_rtap_kept);
  }
  nex_logf("─────────────────────────────────────────────────────────");
}

static void nex_diag_init(void) {
  nex_real_write = (ssize_t (*)(int, const void *, size_t))dlsym(REAL_LIBC, "write");

  const char *dbg = getenv("NEXMON_DEBUG");
  if (dbg && dbg[0])
    nex_dbg = atoi(dbg);

  const char *log = getenv("NEXMON_LOG");
  if (log && log[0]) {
    if (nex_dbg < 1)
      nex_dbg = 1;               /* asking for a log implies wanting output */
    nex_log_fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (nex_log_fd < 0)
      nex_log_fd = -1;
  }

  /* The kernel log, for when the machine is not expected to survive the run —
   * see the note at nex_wr(). Asked for separately and never assumed, because
   * on a healthy run it would only duplicate what NEXMON_LOG already holds. */
  const char *kmsg = getenv("NEXMON_KMSG");
  if (kmsg && kmsg[0] && kmsg[0] != '0') {
    nex_kmsg_fd = open("/dev/kmsg", O_WRONLY);
    if (nex_kmsg_fd < 0)
      nex_kmsg_fd = -1;
  }
}
#endif // ARCH_ARMHF diagnostics

// Process detection flags for tool-specific behavior
static int is_kismet = 0;
static int is_hcxdumptool = 0;
static int is_aireplay = 0;  // Excluded from stability enforcement (causes crashes)

// Additional function pointers for new hooks
static ssize_t (*func_read)(int, void *, size_t) = NULL;
#if defined(ARCH_ARMHF)
// libnl's receive path is recvmsg(), not read() — see the recvmsg() hook near
// the read() hook at the end of this file.
static ssize_t (*func_recvmsg)(int, struct msghdr *, int) = NULL;
#endif

static void nex_restore_radio_defaults(void);  // forward declaration
static void _libmexmon_init() __attribute__((constructor));
static void _libmexmon_fini() __attribute__((destructor));

#if defined(ARCH_ARMHF)
// ── TicWatch Pro 3: which lane does this firmware speak? ─────────────────
// The two nexmon patch families move a frame to the air in different ways and
// the difference is visible from userspace:
//
//   43430/43436 (TicWatch Pro 3) — wl_send_hook on the firmware tx path. The
//     frame is written to the raw socket and the firmware picks it up when it
//     starts with a radiotap header. NEX_GET_CAPABILITIES (400) answers with
//     NEX_CAP_FRAME_INJECTION.
//   bcm4375b1 (S10/S21) — NEX_INJECT_FRAME (408) via ioctl. Command 400 has no
//     case in that patch, so the call fails.
//
// Asking for 400 costs one ioctl at startup and settles the question either
// way. It replaces the driver-name check, which cannot work on the watch: the
// watch runs bcmdhd just like the S10, so the check picked the S10's ioctl
// lane, and command 408 does not exist in any watch firmware. Because the
// injection call sites drop the ioctl return value, that failed silently —
// write() reported the frame length and nothing left the radio.
static int nex_streq_ci(const char *a, const char *b) {
  while (*a && *b) {
    char ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    if (ca != cb) return 0;
    a++;
    b++;
  }
  return *a == 0 && *b == 0;
}

// Reporting only — the driver name no longer selects anything.
static const char *nex_driver_name(void) {
  FILE *f = fopen("/sys/module/brcmfmac/initstate", "r");
  if (f) { fclose(f); return "brcmfmac"; }
  f = fopen("/sys/module/bcmdhd/initstate", "r");
  if (f) { fclose(f); return "bcmdhd"; }
  return "unknown";
}

// Firmware version string as the watch reports it ("9.88.4.65", "7.45.96.79").
// Same call nexutil makes to print it.
static void nex_fw_version(char *out, size_t outsz) {
  char buf[128];
  if (!nexio) { snprintf(out, outsz, "?"); return; }
  memset(buf, 0, sizeof(buf));
  strcpy(buf, "ver");
  if (nex_ioctl(nexio, WLC_GET_VAR, buf, sizeof(buf), false) < 0 || buf[0] == 0) {
    snprintf(out, outsz, "?");
    return;
  }
  buf[sizeof(buf) - 1] = 0;
  // Wide enough for the whole thing: the watch reports
  // "wl0: Mar 16 2025 13:30:46 version 9.88.4.65 (r745790)", and cutting it at
  // 40 characters hides the revision — which is the part that says which
  // fw_bcm*.bin the silicon loaded.
  snprintf(out, outsz, "%.100s", buf);
}

static void nex_detect_injection_method(void) {
  const char *env = getenv("NEXMON_INJECT");
  const char *why;
  int caps = 0;
  int ret_caps = -1, ret_mon = -1;

  if (nexio) {
    ret_caps = nex_ioctl(nexio, NEX_GET_CAPABILITIES, &caps, 4, false);
    nex_dbgf("probe: NEX_GET_CAPABILITIES(400) -> ret=%d caps=0x%x%s", ret_caps, caps,
             ret_caps >= 0 ? "  (firmware implements it: wl_send_hook patch)"
                           : "  (no such command: not a wl_send_hook patch)");
    if (ret_caps < 0) {
      // 400 is unsupported. Check the control channel itself before reading
      // anything into that: WLC_GET_MONITOR is a stock command every patch
      // forwards to the firmware.
      int mon = 0;
      ret_mon = nex_ioctl(nexio, WLC_GET_MONITOR, &mon, 4, false);
      nex_dbgf("probe: WLC_GET_MONITOR(%d) -> ret=%d", WLC_GET_MONITOR, ret_mon);
    }
  }

  if (env && nex_streq_ci(env, "raw")) {
    current_inject_method = INJECT_RAW_SOCKET;
    why = "NEXMON_INJECT=raw";
  } else if (env && nex_streq_ci(env, "ioctl")) {
    current_inject_method = INJECT_IOCTL;
    why = "NEXMON_INJECT=ioctl";
  } else if (ret_caps >= 0) {
    // The patches implementing 400 are exactly the wl_send_hook ones.
    current_inject_method = INJECT_RAW_SOCKET;
    why = (caps & NEX_CAP_FRAME_INJECTION)
              ? "firmware advertises NEX_CAP_FRAME_INJECTION"
              : "firmware implements NEX_GET_CAPABILITIES";
  } else if (ret_mon >= 0) {
    current_inject_method = INJECT_IOCTL;
    why = "firmware rejects NEX_GET_CAPABILITIES (bcm4375b1: NEX_INJECT_FRAME)";
  } else {
    current_inject_method = INJECT_RAW_SOCKET;
    why = "probe inconclusive";
    nex_logf("injection probe inconclusive (caps=%d, monitor=%d) — assuming raw; "
             "override with NEXMON_INJECT=raw|ioctl", ret_caps, ret_mon);
  }

  if (nex_dbg >= 1) {
    char ver[64];
    nex_fw_version(ver, sizeof(ver));
    nex_dbgf("iface=%s driver=%s fw=%s caps=0x%x probe=%d -> inject=%s (%s)",
             ifname, nex_driver_name(), ver, caps, ret_caps,
             (current_inject_method == INJECT_RAW_SOCKET) ? "raw" : "ioctl", why);
  }
}
#endif // ARCH_ARMHF

#if defined(ARCH_ARMHF)
/* What is this process called?
 *
 * The banner below needs it because a tool that spawns a helper per datasource
 * — Kismet starts one process for the Wi-Fi card and further ones for the SDR,
 * Bluetooth and RFID radios it can also drive — re-runs this constructor in
 * every one of them. A pid tells the repeats apart but says nothing about which
 * process owns wlan0, and that is the only one whose silence means anything:
 * seven helpers that print a banner and stop are a fault in the Wi-Fi helper if
 * one of them is the Wi-Fi helper, and a misconfigured datasource if none is.
 *
 * /proc/self/comm is what the delay auto-detection already reads, but the
 * kernel cuts it to 15 characters, which makes kismet_cap_linux_wifi and
 * kismet_cap_linux_bluetooth both read as "kismet_cap_linu". cmdline keeps the
 * whole word, so it is tried first and comm is only the fallback. */
static void nex_proc_name(char *out, size_t outsz) {
  out[0] = 0;

  FILE *f = fopen("/proc/self/cmdline", "r");
  if (f) {
    // argv[0] ends at the first NUL and %s stops there; the rest of the
    // command line trails behind it in the buffer and is simply not printed.
    if (fgets(out, outsz, f)) {
      const char *base = strrchr(out, '/');
      if (base) memmove(out, base + 1, strlen(base + 1) + 1);
    }
    fclose(f);
  }

  if (out[0] == 0) {
    f = fopen("/proc/self/comm", "r");
    if (f) {
      if (fgets(out, outsz, f)) {
        char *nl = strchr(out, '\n');
        if (nl) *nl = 0;
      }
      fclose(f);
    }
  }

  if (out[0] == 0) snprintf(out, outsz, "?");
}
#endif // ARCH_ARMHF

static void _libmexmon_init() {
#if defined(ARCH_ARMHF)
  // First thing: get the log open and the real write(2) in hand, so that
  // everything after this point can be reported.
  nex_diag_init();
#endif

  // Allow interface name override via environment (default: wlan0)
  const char *iface_env = getenv("NEXMON_IFACE");
  if (iface_env && iface_env[0]) {
      ifname = iface_env;
  }

  nexio = nex_init_ioctl(ifname);
  if (!nexio || !nexio->ifr) {
      fprintf(stderr, "LIBNEXMON: FATAL — nex_init_ioctl(\"%s\") failed (out of memory?)\n", ifname);
      return; // Cannot proceed without nexio
  }

#if defined(ARCH_ARMHF)
  // The TicWatch Pro 3 runs bcmdhd — the same driver as the S10 — but its
  // firmware has no NEX_INJECT_FRAME: it injects through the tx path instead.
  // The driver name says nothing useful about that, so the lane is left at the
  // raw default and the firmware probe below settles it, once dlsym() has
  // resolved the ioctl() it needs.
#else
  // Universal Driver Detection
  // Determine injection method based on which driver is loaded
  {
      FILE *f_brcmfmac = fopen("/sys/module/brcmfmac/initstate", "r");
      FILE *f_bcmdhd = fopen("/sys/module/bcmdhd/initstate", "r");

      if (f_brcmfmac) {
          current_inject_method = INJECT_RAW_SOCKET;
          fclose(f_brcmfmac);
      } else if (f_bcmdhd) {
          current_inject_method = INJECT_IOCTL;
          fclose(f_bcmdhd);
      } else {
          // Fallback based on architecture defines from Makefile
#if defined(ARCH_ARMHF)
          current_inject_method = INJECT_RAW_SOCKET; // Assume brcmfmac pattern for armhf
#else
          current_inject_method = INJECT_IOCTL;      // Assume bcmdhd pattern for aarch64
#endif
      }
  }
#endif

  // Radio stabilization delay - helps when switching between attacks
  // When wifite spawns a new attack process, this gives the firmware
  // time to recover from the previous attack's state
  struct timespec init_delay = {.tv_sec = 0, .tv_nsec = (current_inject_method == INJECT_RAW_SOCKET) ? 20000000 : 10000000};
  nanosleep(&init_delay, NULL);

  // Performance Optimization: Configurable Delay & Smart Auto-Detect
  // Priority 1: User Override via environment variable
  const char *delay_env = getenv("NEXMON_DELAY");
  if (delay_env) {
      long val = atol(delay_env);
      if (val >= 0) {
          inject_delay_ns = val;
      }
  } else {
      // Priority 2: Smart Auto-Detect based on Process Name
      char proc_name[256] = {0};
      FILE *f = fopen("/proc/self/comm", "r");
      if (f) {
          fread(proc_name, 1, sizeof(proc_name)-1, f);
          fclose(f);
          // Strip newline
          char *nl = strchr(proc_name, '\n');
          if (nl) *nl = 0;

          // Reaver and Bully: 5ms (Aggressive but with a tiny breathing room)
          if (strstr(proc_name, "reaver") || strstr(proc_name, "bully")) {
              inject_delay_ns = 5000000; // 5ms
              // fprintf(stderr, "LIBNEXMON: Auto-detected %s - Setting MAX SPEED (5ms)\n", proc_name);
          }
          // Aireplay-ng: 15ms (High Speed)
          else if (strstr(proc_name, "aireplay")) {
              is_aireplay = 1;  // Flag to exclude from stability enforcement
              inject_delay_ns = 15000000; // 15ms
              // fprintf(stderr, "LIBNEXMON: Auto-detected %s - Setting HIGH SPEED (15ms)\n", proc_name);
          }
          // Airodump-ng: 40ms (Moderate Speed for active scanning)
          else if (strstr(proc_name, "airodump")) {
             inject_delay_ns = 40000000; // 40ms
             // fprintf(stderr, "LIBNEXMON: Auto-detected %s - Setting MONITOR SPEED (40ms)\n", proc_name);
          }
          // Kismet: 20ms (Balanced for scanning, needs stability enforcement)
          else if (strstr(proc_name, "kismet")) {
              is_kismet = 1;
              inject_delay_ns = 20000000; // 20ms
              // fprintf(stderr, "LIBNEXMON: Auto-detected Kismet - Setting SCAN SPEED (20ms)\n");
          }
          // hcxdumptool: 10ms (Aggressive capture, needs stability enforcement)
          else if (strstr(proc_name, "hcxdumptool")) {
              is_hcxdumptool = 1;
              inject_delay_ns = 10000000; // 10ms
              // fprintf(stderr, "LIBNEXMON: Auto-detected hcxdumptool - Setting CAPTURE SPEED (10ms)\n");
          }
          // Default for unknown tools remains 70ms (Safe Mode)
      }
  }

  // Raw socket injection tuning (often constrained armhf chips like TicWatch/RPi)
  // Increase default delay if user hasn't overridden and no tool auto-detected
  if (current_inject_method == INJECT_RAW_SOCKET && !delay_env && inject_delay_ns == 70000000) {
      inject_delay_ns = 100000000; // 100ms default for constrained chips
  }

#if defined(ARCH_ARMHF)
  nex_dbgf("inject delay = %ld ms (%s)", inject_delay_ns / 1000000,
           delay_env       ? "from NEXMON_DELAY"
           : nex_dbg >= 2  ? "auto-detected from /proc/self/comm, or default"
                           : "auto-detected or default");
#endif

  if (!func_ioctl)
    func_ioctl = (int (*)(int, request_t, void *))dlsym(REAL_LIBC, "ioctl");

  if (!func_socket)
    func_socket = (int (*)(int, int, int))dlsym(REAL_LIBC, "socket");

  if (!func_bind)
    func_bind =
        (int (*)(int, const struct sockaddr *, int))dlsym(REAL_LIBC, "bind");

  if (!func_write)
    func_write = (ssize_t (*)(int, const void *, size_t))dlsym(REAL_LIBC, "write");

  if (!func_sendto)
    func_sendto =
        (int (*)(int, const void *, size_t, int, const struct sockaddr *,
                 socklen_t))dlsym(REAL_LIBC, "sendto");

  if (!func_sendmsg)
    func_sendmsg = (ssize_t (*)(int, const struct msghdr *, int))dlsym(
        REAL_LIBC, "sendmsg");

  if (!func_send)
    func_send =
        (ssize_t (*)(int, const void *, size_t, int))dlsym(REAL_LIBC, "send");

  if (!func_sendmmsg)
    func_sendmmsg = (int (*)(int, struct mmsghdr *, unsigned int, int))dlsym(
        REAL_LIBC, "sendmmsg");

#ifdef CONFIG_LIBNL
  if (!func_nl_send_auto_complete)
    func_nl_send_auto_complete =
        (int (*)(struct nl_sock *, struct nl_msg *))dlsym(
            REAL_LIBNL, "nl_send_auto_complete");
#endif // CONFIG_LIBNL

  if (!func_read)
    func_read = (ssize_t (*)(int, void *, size_t))dlsym(REAL_LIBC, "read");

#if defined(ARCH_ARMHF)
  // The other name libnl's receive arrives under — see the recvmsg() hook.
  // On a 32-bit-time armhf toolchain the plain name is never the one that gets
  // called, so both spellings are resolved and the hook is exported under both.
  if (!func_recvmsg)
    func_recvmsg = (ssize_t (*)(int, struct msghdr *, int))dlsym(REAL_LIBC, "recvmsg");
  if (!func_recvmsg)
    func_recvmsg = (ssize_t (*)(int, struct msghdr *, int))dlsym(REAL_LIBC, "__recvmsg64");
#endif

#if defined(ARCH_ARMHF)
  // A symbol that failed to resolve shows up later as a hook that silently
  // does nothing or a null call, so say so now rather than let it be deduced.
  {
    const char *missing = NULL;
    if (!func_write)       missing = "write";
    else if (!func_ioctl)  missing = "ioctl";
    else if (!func_socket) missing = "socket";
    else if (!func_bind)   missing = "bind";
    else if (!func_sendto) missing = "sendto";
    else if (!func_send)   missing = "send";
    else if (!func_sendmsg) missing = "sendmsg";
    else if (!func_sendmmsg) missing = "sendmmsg";
    else if (!func_read)   missing = "read";
    else if (!func_recvmsg) missing = "recvmsg";
    if (missing)
      nex_logf("WARNING: dlsym() could not resolve %s — that hook is dead", missing);
  }

  if (getenv("NEXMON_RAW_NO_RADIOTAP")) {
    nex_radiotap_disabled = 1;
    nex_dbgf("NEXMON_RAW_NO_RADIOTAP set — frames go out exactly as given, "
             "with no preamble (wl_send_hook will drop bare ones)");
  }

  // Ask the firmware which injection lane it speaks. This has to run after
  // dlsym(): nex_ioctl() reaches the kernel through the ioctl() hook below,
  // which passes the call on with func_ioctl.
  nex_detect_injection_method();

  if (current_inject_method == INJECT_RAW_SOCKET)
    nex_dbgf("lane is raw — every injected frame needs a radiotap header, "
             "and wlc->monitor must already be set (`nexutil -m2`)");

  // Printed last so it closes the banner. A tool that shells out to helpers
  // re-runs this constructor in every process it spawns, and without a pid
  // those repeats are indistinguishable from one process loading twice. The
  // name is the other half of that: it says which of those processes is the
  // one holding the interface.
  {
    char proc[64];
    nex_proc_name(proc, sizeof(proc));
    nex_dbgf("pid %ld (%s) loaded the shim for \"%s\" (lane=%s)", (long)getpid(), proc,
             ifname, current_inject_method == INJECT_RAW_SOCKET ? "raw" : "ioctl");
  }
#endif
}

// Destructor: clean up when library is unloaded (e.g., tool exits, nxsp unload)
// Restores radio to managed-mode defaults so WiFi works normally after
static void _libmexmon_fini() {
#if defined(ARCH_ARMHF)
    // Print the tally before the radio is put back, so the record survives the
    // tool's exit. Only reached on a clean exit — a SIGKILL loses it, which is
    // what NEXMON_LOG is for.
    nex_dump_summary();
#endif
    nex_restore_radio_defaults();
}

#ifdef CONFIG_LIBNL
static int _nl80211_type = 0;
int nl80211_type() {
  if (_nl80211_type) {
    // fprintf(stderr, "cached\n");
    return _nl80211_type;
  }

  int rval;
  struct nl_sock *nl_sock = NULL;
  struct nl_cache *nl_cache = NULL;
  struct genl_family *nl80211 = NULL;

  // fprintf(stderr, "beginning\n");
  nl_sock = nl_socket_alloc();
  // fprintf(stderr, "nl_sock=%d\n", nl_sock);
  if (!nl_sock)
    return 0;

  rval = genl_connect(nl_sock);
  // fprintf(stderr, "genl_connect=%d\n", rval);
  if (rval) {
    nl_socket_free(nl_sock);
    return 0;
  }

  rval = genl_ctrl_alloc_cache(nl_sock, &nl_cache);
  // fprintf(stderr, "genl_ctrl_allocate_cache=%d\n", rval);
  if (rval) {
    nl_socket_free(nl_sock);
    return 0;
  }

  nl80211 = genl_ctrl_search_by_name(nl_cache, "nl80211");
  // fprintf(stderr, "genl_ctrl_search_by_name=%d\n", !!nl80211);

  if (nl80211) {
    _nl80211_type = genl_family_get_id(nl80211);
    // fprintf(stderr, "_nl80211_type=%d\n", _nl80211_type);
  }

  nl_cache_free(nl_cache);
  nl_socket_free(nl_sock);
  return _nl80211_type;
}

// Stability enforcement - called after channel changes for compatible tools
// This prevents the radio from going "deaf" (waiting for beacon) during scans
// Also called periodically during handshake capture to keep radio awake
// Note: Limited firmware variants may not support WLC_SET_WAKE/SCANSUPPRESS but errors are
// silently ignored by nex_ioctl (returns -1), so this is safe across all chips.
#if defined(ARCH_ARMHF)
/* Whether the four ioctls below run at all, asked once and remembered.
 *
 * On the watch they are off unless NEXMON_STABILITY=1 says otherwise, and the
 * reason is what happened the last time they ran. With Kismet driving the
 * interface these fire after every channel hop — four WLC ioctls per hop, PM,
 * WAKE, SCANSUPPRESS and PROMISC — and the watch rebooted twice, the second
 * time with dhd re-downloading firmware two seconds before the system died
 * (pstore console-ramoops: dhd_conf_set_path_params, then "Fatal error on the
 * modem"). A dongle that has to be reloaded mid-capture is the crash, not the
 * cure.
 *
 * They are not load-bearing either. airodump-ng hops channels through WEXT and
 * never reaches this function at all, and it captures on the watch without any
 * of it. Turning them back on is one environment variable, so the question
 * stays a measurement rather than an argument. */
static int nex_stability_on(void) {
  static int cached = -1;
  if (cached < 0) {
    const char *e = getenv("NEXMON_STABILITY");
    cached = (e && e[0] && e[0] != '0') ? 1 : 0;
    nex_dbgf("stability ioctls after channel hops: %s",
             cached ? "ON (NEXMON_STABILITY set)" : "off");
  }
  return cached;
}
#endif

static void nex_enforce_stability(void) {
    // Skip for aireplay-ng - causes crashes during deauth floods
    if (is_aireplay) return;

#if defined(ARCH_ARMHF)
    if (!nex_stability_on()) return;
#endif

    int val;
    
    // WLC_SET_PM = 0 (Constantly Awake Mode - CAM)
    val = 0;
    nex_ioctl(nexio, WLC_SET_PM, &val, 4, true);
    
    // WLC_SET_WAKE = 1 (Force wake, prevent sleep)
    // May return error on some variants - that's OK, silently ignored
    val = 1;
    nex_ioctl(nexio, WLC_SET_WAKE, &val, 4, true);
    
    // WLC_SET_SCANSUPPRESS = 1 (Suppress background scans)
    // May return error on some variants - that's OK, silently ignored
    val = 1;
    nex_ioctl(nexio, WLC_SET_SCANSUPPRESS, &val, 4, true);
    
    // WLC_SET_PROMISC = 1 (Promiscuous Mode)
    val = 1;
    nex_ioctl(nexio, WLC_SET_PROMISC, &val, 4, true);
}

// Restore radio to normal managed-mode defaults
// Called when monitor mode is turned off and when the library is unloaded
// This reverses everything nex_enforce_stability() does, allowing the
// driver to scan for networks and associate normally again.
static void nex_restore_radio_defaults(void) {
    if (!nexio) return;
    
    int val;
    
    // WLC_SET_SCANSUPPRESS = 0 (Re-enable background scans)
    // THIS IS THE CRITICAL ONE: without this, "no networks found" after monitor off
    val = 0;
    nex_ioctl(nexio, WLC_SET_SCANSUPPRESS, &val, 4, true);
    
    // WLC_SET_PROMISC = 0 (Disable promiscuous mode)
    // Must be off for normal association/scanning to work
    val = 0;
    nex_ioctl(nexio, WLC_SET_PROMISC, &val, 4, true);
    
    // WLC_SET_PM = 2 (Fast Power Save - Android default)
    // Restores normal power management so battery isn't drained
    val = 2;
    nex_ioctl(nexio, WLC_SET_PM, &val, 4, true);
    
    // WLC_SET_WAKE = 0 (Allow sleep - normal behavior)
    val = 0;
    nex_ioctl(nexio, WLC_SET_WAKE, &val, 4, true);
}

#if defined(ARCH_ARMHF)
/* ── Kismet's netlink lane ────────────────────────────────────────────────
 *
 * Kismet does its nl80211 work through libnl, and the shape of libnl decides
 * two things this library has to answer for.
 *
 * 1. Every send is answered by a wait. Kismet's capture helper calls
 *    nl_send_auto_complete() and then nl_wait_for_ack(), and every failure
 *    check it makes is `send < 0 || wait < 0` — the wait is what produces the
 *    error. So the SET_INTERFACE fake below has to be remembered: it returns a
 *    byte count without sending anything, no ACK can ever arrive for it, and
 *    nl_wait_for_ack() on a socket with nothing outstanding never returns. That
 *    is the hang — the helper sits in its datasource setup for ever and the
 *    server never gets as far as printing anything, which is what the watch's
 *    kismet log shows.
 *
 * 2. Receive is recvmsg(), not read(). libnl fills one iovec and hands it to
 *    recvmsg() (libnl 3.12 here, and the peek/real pair handled below comes
 *    from the same reading of nl_recv()). The suppression that rewrites a
 *    rejected command into a success therefore belongs in a recvmsg() hook;
 *    the read() hook further down is only reached by tools that read netlink
 *    themselves.
 *
 * What gets rewritten stays narrow. Only SET_WIPHY is, because this library
 * genuinely performs that request on the firmware side (nex_set_channel_full),
 * so hiding the kernel's refusal is truthful rather than a lie. An NLMSG_ERROR
 * carries only the rejected message's header — its type, length and sequence
 * number — and not the genl command, so outgoing commands are remembered here
 * by sequence number and looked up when the error comes back. NEW_INTERFACE
 * must keep failing: when Kismet cannot create its monitor vif it falls back to
 * capturing on the interface it was handed, and hiding that failure would send
 * it to capture from a vif that does not exist.
 *
 * None of this is compiled for aarch64 — the S10 lane has no kismet helper to
 * stay in step with, and its build stays byte for byte what it was.
 */
#define NEX_NL_SEEN 32   /* outgoing commands remembered, keyed by sequence */
#define NEX_NL_FAKES 4   /* faked sends still awaiting their nl_wait_for_ack */

static struct {
  unsigned seq;
  unsigned short type; /* nlmsg_type the command went out as (nl80211 family) */
  unsigned char cmd;   /* genl command */
} nex_nl_seen[NEX_NL_SEEN];
static unsigned nex_nl_seen_next;

static struct nl_sock *nex_nl_fake_pending[NEX_NL_FAKES];

static void nex_nl_remember(unsigned seq, unsigned short type, unsigned char cmd) {
  nex_nl_seen[nex_nl_seen_next].seq = seq;
  nex_nl_seen[nex_nl_seen_next].type = type;
  nex_nl_seen[nex_nl_seen_next].cmd = cmd;
  nex_nl_seen_next = (nex_nl_seen_next + 1) % NEX_NL_SEEN;
}

/* Was this reply the answer to a request this library carried out itself? The
 * sequence number is the only link there is: the kernel copies the rejected
 * request's header into the error, and that header names the family but not the
 * genl command. */
static int nex_nl_reply_is(unsigned seq, unsigned short type, unsigned char cmd) {
  unsigned i;
  for (i = 0; i < NEX_NL_SEEN; i++)
    if (nex_nl_seen[i].seq == seq && nex_nl_seen[i].type == type &&
        nex_nl_seen[i].cmd == cmd)
      return 1;
  return 0;
}

/* A faked send, and the wait about to be made for it. A wait cannot name the
 * request it is waiting for, so the pairing is positional: a send on a socket
 * clears anything still pending on it (Kismet's helper is strictly send, wait,
 * send, wait), and the next wait takes what is there. A fake that is never
 * waited for is dropped by the next send rather than left armed for a later
 * command to trip over. */
static void nex_nl_fake_clear(struct nl_sock *sk) {
  unsigned i;
  for (i = 0; i < NEX_NL_FAKES; i++)
    if (nex_nl_fake_pending[i] == sk)
      nex_nl_fake_pending[i] = NULL;
}

static void nex_nl_fake_add(struct nl_sock *sk) {
  unsigned i;
  for (i = 0; i < NEX_NL_FAKES; i++) {
    if (!nex_nl_fake_pending[i]) {
      nex_nl_fake_pending[i] = sk;
      return;
    }
  }
  /* Every slot taken, which takes four sockets each waiting on a fake at once.
   * The first is then the least likely to still be waited for. */
  nex_nl_fake_pending[0] = sk;
}

static int nex_nl_fake_take(struct nl_sock *sk) {
  unsigned i;
  for (i = 0; i < NEX_NL_FAKES; i++) {
    if (nex_nl_fake_pending[i] == sk) {
      nex_nl_fake_pending[i] = NULL;
      return 1;
    }
  }
  return 0;
}

/* What the tools actually ask nl80211 for, named once each.
 *
 * This is the requirement list, and it is taken from the traffic rather than
 * from a reading of nl80211.h — the difference matters, because the header
 * describes several hundred commands and the useful question is which handful
 * arrive on this device. Each is reported the first time it is seen and never
 * again: a tool that hops a channel a second would otherwise bury the log. */
static unsigned char nex_nl_cmd_seen[256];

static const char *nex_nl_cmd_name(unsigned char cmd) {
  switch (cmd) {
    case NL80211_CMD_GET_WIPHY: return "GET_WIPHY";
    case NL80211_CMD_SET_WIPHY: return "SET_WIPHY";
    case NL80211_CMD_NEW_WIPHY: return "NEW_WIPHY";
    case NL80211_CMD_GET_INTERFACE: return "GET_INTERFACE";
    case NL80211_CMD_SET_INTERFACE: return "SET_INTERFACE";
    case NL80211_CMD_NEW_INTERFACE: return "NEW_INTERFACE";
    case NL80211_CMD_DEL_INTERFACE: return "DEL_INTERFACE";
    case NL80211_CMD_SET_CHANNEL: return "SET_CHANNEL";
    case NL80211_CMD_GET_KEY: return "GET_KEY";
    case NL80211_CMD_SET_KEY: return "SET_KEY";
    case NL80211_CMD_GET_STATION: return "GET_STATION";
    case NL80211_CMD_SET_STATION: return "SET_STATION";
    case NL80211_CMD_GET_SCAN: return "GET_SCAN";
    case NL80211_CMD_TRIGGER_SCAN: return "TRIGGER_SCAN";
    case NL80211_CMD_GET_REG: return "GET_REG";
    case NL80211_CMD_GET_PROTOCOL_FEATURES: return "GET_PROTOCOL_FEATURES";
    case NL80211_CMD_CONNECT: return "CONNECT";
    case NL80211_CMD_DISCONNECT: return "DISCONNECT";
    case NL80211_CMD_AUTHENTICATE: return "AUTHENTICATE";
    case NL80211_CMD_ASSOCIATE: return "ASSOCIATE";
    case NL80211_CMD_REGISTER_FRAME: return "REGISTER_FRAME";
    case NL80211_CMD_FRAME: return "FRAME";
    default: return NULL;
  }
}

static void nex_nl_note_cmd(unsigned char cmd) {
  const char *n;
  if (nex_nl_cmd_seen[cmd])
    return;
  nex_nl_cmd_seen[cmd] = 1;
  n = nex_nl_cmd_name(cmd);
  if (n)
    nex_dbgf("nl80211 asks for: %s (%u)", n, cmd);
  else
    nex_dbgf("nl80211 asks for: command %u (unnamed here)", cmd);
}
#endif /* ARCH_ARMHF */

int handle_nl_msg(struct nl_msg *msg) {
  int retval;
  struct nlmsghdr *nlh;
  struct genlmsghdr *ghdr;
  struct nlattr *attr[NL80211_ATTR_MAX + 1];
#if defined(ARCH_ARMHF)
  /* The policy array has to be as long as the maxtype it is handed: libnl's
   * validate_nla() indexes policy[type] for every attribute up to maxtype, so
   * the four entries this used to have were read past their end by any message
   * carrying an attribute type of 4 or more — which is every SET_WIPHY (freq is
   * 38) and every NEW_INTERFACE. What it read was whatever sat next on the
   * stack; when that was not a valid type, libnl's own BUG() aborted the
   * process out from under the tool. Kismet sends NEW_INTERFACE on startup, and
   * a helper that dies there produces exactly the run that shows nothing at
   * all: the shim's banner, then silence.
   *
   * All-zero entries mean NLA_UNSPEC and no minimum length, so nothing is
   * rejected that this code does not read itself. Left as it was on aarch64:
   * the S10 lane is built byte for byte as it shipped. */
  struct nla_policy policy[NL80211_ATTR_MAX + 1] = {{0}};
#else
  struct nla_policy policy[4] = {
      [0] = {.type = NLA_U32},
  };
#endif

  nlh = nlmsg_hdr(msg);

  // if this isn't an nl80211 message, we don't want it
  if (nlh->nlmsg_type != nl80211_type())
    return 0;
  if (nlmsg_get_proto(msg) != NETLINK_GENERIC)
    return 0;

  // fprintf(stderr, "nlmsg_parse\n");
  retval = nlmsg_parse(nlh, GENL_HDRLEN, attr, NL80211_ATTR_MAX, policy);
  // fprintf(stderr, "retval=%d\n", retval);
  if (retval)
    return 0;

  ghdr = nlmsg_data(nlh);
  /* SET_CHANNEL is the pre-3.8 spelling of the same request — same attributes,
   * same meaning. It is still what some tools emit, and a tool old enough to
   * send it means what SET_WIPHY means: go to this channel. Kept behind the
   * preprocessor so that aarch64 expands back to the single test it had and
   * the S10 build stays byte for byte what it was. */
  if (ghdr->cmd == NL80211_CMD_SET_WIPHY
#if defined(ARCH_ARMHF)
      || ghdr->cmd == NL80211_CMD_SET_CHANNEL
#endif
  ) {
    int chan = 0;
    int ht_mode = NL80211_CHAN_HT20;
    int bandwidth = WL_CHANSPEC_BW_20;
    int band = WL_CHANSPEC_BAND_2G;
    int ctl_sb = 0;
#if defined(ARCH_ARMHF)
    /* The channel the request actually names, kept apart from the one the code
     * below derives from it. A 40 MHz request is two frequencies — a control
     * frequency and a centre frequency 10 MHz away — and the centre is not a
     * channel this radio can be tuned to; see the call site further down. */
    int ctrl_chan = 0;
#endif

    if (!attr[NL80211_ATTR_IFINDEX])
      return 0;
    if (nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
      return 0;
    // fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n",
    // nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

    if (attr[NL80211_ATTR_WIPHY_FREQ]) {
      int freq = nla_get_u32(attr[NL80211_ATTR_WIPHY_FREQ]);
      chan = frequency_to_channel(freq);
#if defined(ARCH_ARMHF)
      ctrl_chan = chan;
#endif
      if (freq >= 5000)
        band = WL_CHANSPEC_BAND_5G;
      // fprintf(stderr, "NL80211_ATTR_WIPHY_FREQ = %u (%d)\n", freq, chan);
    }
    // HT20/HT40-/HT40+/...  there are more but our device doesn't support that
    // anyway
    if (attr[NL80211_ATTR_WIPHY_CHANNEL_TYPE]) {
      ht_mode = nla_get_u32(attr[NL80211_ATTR_WIPHY_CHANNEL_TYPE]);
      // fprintf(stderr, "NL80211_ATTR_WIPHY_CHANNEL_TYPE = %u\n",
      // nla_get_u32(attr[NL80211_ATTR_WIPHY_CHANNEL_TYPE]));
    }
    if (attr[NL80211_ATTR_CHANNEL_WIDTH]) {
      if (nla_get_u32(attr[NL80211_ATTR_CHANNEL_WIDTH]) ==
          NL80211_CHAN_WIDTH_40)
        bandwidth = WL_CHANSPEC_BW_40;
      // fprintf(stderr, "NL80211_ATTR_CHANNEL_WIDTH = %u\n",
      // nla_get_u32(attr[NL80211_ATTR_CHANNEL_WIDTH]));
    }
    if (attr[NL80211_ATTR_CENTER_FREQ1]) {
      int freq = nla_get_u32(attr[NL80211_ATTR_CENTER_FREQ1]);
      int ctl_chan = frequency_to_channel(freq);
      if (ctl_chan > chan)
        ctl_sb = WL_CHANSPEC_CTL_SB_LLL;
      else if (ctl_chan < chan)
        ctl_sb = WL_CHANSPEC_CTL_SB_LLU;
      chan = ctl_chan;
      // fprintf(stderr, "NL80211_ATTR_CENTER_FREQ1 = %u\n", freq,
      // frequency_to_channel(freq));
    }
    // this device doesn't support 80+80 anyway
    // if(attr[NL80211_ATTR_CENTER_FREQ2])
    //	fprintf(stderr, "NL80211_ATTR_CENTER_FREQ2 = %u\n",
    // nla_get_u32(attr[NL80211_ATTR_CENTER_FREQ2]));

    if (ht_mode == NL80211_CHAN_HT40PLUS) {
      if (band == WL_CHANSPEC_BAND_2G) {
        bandwidth = WL_CHANSPEC_BW_40;
        chan = LOWER_20_SB(chan);
        ctl_sb = WL_CHANSPEC_CTL_SB_LLU;
      } else
        ht_mode = NL80211_CHAN_HT40MINUS; // there is only one sideband allowed
                                          // for 40MHz in 5G band
    }
    if (ht_mode == NL80211_CHAN_HT40MINUS) {
      bandwidth = WL_CHANSPEC_BW_40;
      chan = UPPER_20_SB(chan);
      ctl_sb = WL_CHANSPEC_CTL_SB_LLL;
    }

    if (chan) {
#if defined(ARCH_ARMHF)
      /* What the tools ask for, translated into what this radio has.
       *
       * Kismet builds its hop list from the kernel's own report of this phy and
       * its shipped source definition asks for HT and VHT channels, so what
       * arrives here includes 40 MHz pairs — and it can include 5 GHz, because
       * Kismet reads the bands out of the driver's cfg80211 registration and
       * takes what it finds there at face value. The radio behind this lane is
       * 2.4 GHz only, and its monitor mode is a 20 MHz affair.
       *
       * A chanspec the firmware cannot honour is how this watch's dongle ends up
       * reloading its firmware from scratch: the pstore log from the run that
       * died shows dhd fetching fw_bcm43438a1.bin two seconds before the system
       * went. So the request is translated rather than forwarded — the channel
       * the request names is kept, the width becomes the one monitor mode runs
       * at, and a channel this radio does not have is refused here, in the
       * library, instead of at the firmware.
       *
       * The 40 MHz case needs the translation most. Above, a request for a
       * 2.4 GHz channel in HT40 reads the attribute pair as the pair it is:
       * control frequency 2432 and centre frequency 2422 name channel 5 bonded
       * upward, and the code turns that into "tune to channel 3, 40 MHz wide".
       * The channel field of a Broadcom chanspec carries the control channel,
       * so channel 3 with 40 MHz described a segment that does not exist, and
       * that went to the firmware. ctrl_chan is the control channel the request
       * began with, and it is what gets tuned. */
      if (band == WL_CHANSPEC_BAND_5G) {
        nex_dbgf("nl80211 SET_WIPHY: a 5 GHz channel was asked for; this radio "
                 "has only 2.4 GHz, so nothing is sent to a firmware that could "
                 "not tune it");
        return 0;
      }
      if (ctrl_chan && ctrl_chan != chan) {
        nex_dbgf("nl80211 SET_WIPHY: 40 MHz request, control channel %d (the pair "
                 "centres on %d); tuning control channel %d at 20 MHz, the width "
                 "this radio's monitor mode runs at",
                 ctrl_chan, chan, ctrl_chan);
        chan = ctrl_chan;
      }
      if (chan < 1 || chan > CH_MAX_2G_CHANNEL) {
        nex_dbgf("nl80211 SET_WIPHY: channel %d is outside this radio's range "
                 "(1-%d); request dropped", chan, CH_MAX_2G_CHANNEL);
        return 0;
      }
      bandwidth = WL_CHANSPEC_BW_20;
      ctl_sb = 0;
      /* Same as SIOCSIWFREQ: what the tool joins on must be recorded for the
       * association lane, since half the suite tunes through nl80211. */
      nex_assoc_note_channel(chan);
#endif
      // nex_set_channel_simple(chan);
      int ret = nex_set_channel_full(chan, band, bandwidth, ctl_sb);
#if defined(ARCH_ARMHF)
      nex_nl_chan++;
      nex_dbgf("nl80211 SET_WIPHY: channel %d (band %s, bw %s) -> ret=%d", chan,
               band == WL_CHANSPEC_BAND_5G ? "5G" : "2.4G",
               bandwidth == WL_CHANSPEC_BW_40 ? "40" : "20", ret);
#endif
      // Enforce stability after channel hop (for Kismet/hcxdumptool)
      // This prevents the radio from going "deaf" after switching channels
      if (is_kismet || is_hcxdumptool) {
        nex_enforce_stability();
      }
      return ret;
    }
  }
  if (ghdr->cmd == NL80211_CMD_SET_INTERFACE) {
    if (!attr[NL80211_ATTR_IFINDEX])
      return 0;
    if (nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
      return 0;
    // fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n",
    // nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

    // we could set monitor/managed mode based on this message
    // Deliberately not done. Kismet and hcxdumptool come through here asking
    // for monitor mode that is already active (set with `nexutil -m2` from the
    // Android side), and re-enabling it crashes the firmware. Acting on a
    // request for IFTYPE_STATION would be worse still — it would tear down a
    // monitor mode the tool never asked to leave.
    if (attr[NL80211_ATTR_IFTYPE]) {
      // fprintf(stderr, "NL80211_ATTR_IFTYPE = %u\n",
      // nla_get_u32(attr[NL80211_ATTR_IFTYPE]));
    }
  }

  return 0;
}

// there are several other functions that can send netlink messages, but it
// looks like airodump-ng and kismet both use this one, so this is good enough
// for now
int nl_send_auto_complete(struct nl_sock *sk, struct nl_msg *msg) {
  int ret;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct genlmsghdr *ghdr = nlmsg_data(nlh);

#if defined(ARCH_ARMHF)
  // Whatever was sent on this socket before was waited for, or never will be;
  // either way its fake is stale now. See the note above nex_nl_fake_add().
  nex_nl_fake_clear(sk);
#endif

  // Intercept NL80211_CMD_SET_INTERFACE for Kismet/hcxdumptool
  // These tools try to set monitor mode via netlink, which the Android kernel rejects
  // We fake a success response to prevent them from aborting
  // The fake must stay a pure no-op. Monitor mode is already on — it is set
  // with `nexutil -m2` before the tool starts — and performing this request
  // would be a redundant re-enable, which crashes the firmware. Kismet asks
  // for it unconditionally on startup, so the answer is to satisfy it here
  // and touch nothing on the radio.
  /* Which processes get the fake.
   *
   * On the watch: all of them. Any interface-mode change that reaches the
   * driver is a change the firmware has to survive, and this is the request
   * that asks it to go into monitor mode a second time — the one that killed
   * it. Nothing is lost by answering it here, because the mode the tool wants
   * is the mode the radio is already in (set with `nexutil -m2`), and the
   * netlink view stays self-consistent: the same lane answers GET_INTERFACE.
   * On the S10 it stays as it was, kismet and hcxdumptool only. */
  #if defined(ARCH_ARMHF)
  // The requirement list, taken from the traffic: whatever this process asks
  // nl80211 for, named once. A tool that hops a channel a second would make a
  // per-request log useless, so each command is reported on first sight only.
  if (nlh->nlmsg_type == nl80211_type())
    nex_nl_note_cmd(ghdr->cmd);
#endif

  if (
#if defined(ARCH_ARMHF)
      1 && /* every process on the watch — see the note above */
#else
      (is_kismet || is_hcxdumptool) &&
#endif
      nlh->nlmsg_type == nl80211_type() &&
      ghdr->cmd == NL80211_CMD_SET_INTERFACE) {
#if defined(ARCH_ARMHF)
    char proc[64];
    nex_proc_name(proc, sizeof(proc));
    nex_nl_faked++;
    // Record it for the wait that is about to be made. Kismet's next call is
    // nl_wait_for_ack(), which would otherwise wait for ever: nothing was sent,
    // so no ACK is coming. That wait is answered in the nl_wait_for_ack() hook.
    nex_nl_fake_add(sk);
    nex_dbgf("nl80211 SET_INTERFACE: faked success for %s and left the radio "
             "alone (re-enabling monitor mode crashes the firmware — see the "
             "note above); the ACK it waits for next is answered here so it "
             "does not block on a reply that was never requested", proc);
#endif
    // Return fake success (simulate the bytes that would have been sent)
    // This prevents EINVAL/EOPNOTSUPP errors from crashing the tools
    return nlmsg_total_size(nlmsg_datalen(nlh));
  }

  ret = func_nl_send_auto_complete(sk, msg);

#if defined(ARCH_ARMHF)
  // Remember which command left under this sequence number, so that the error
  // that comes back can be told apart from one this library has to keep. An
  // NLMSG_ERROR quotes the rejected header and nothing else.
  nex_nl_remember(nlh->nlmsg_seq, nlh->nlmsg_type, ghdr->cmd);
#endif

  // fprintf(stderr, "\nnl_send_auto_complete()\n");
  handle_nl_msg(msg);
  return ret;
}
#endif // CONFIG_LIBNL

int frequency_to_channel(int freq_in_MHz) {
  if (freq_in_MHz == 2484)
    return 14;
  if (freq_in_MHz >= 2412 && freq_in_MHz <= 2472)
    return (freq_in_MHz - 2407) / 5;
  if (freq_in_MHz >= 5000 && freq_in_MHz <= 6000)
    return (freq_in_MHz - 5000) / 5;

  return 0;
}

int nex_set_channel_simple(int channel) {
  int band = ((channel <= CH_MAX_2G_CHANNEL) ? WL_CHANSPEC_BAND_2G
                                             : WL_CHANSPEC_BAND_5G);
  return nex_set_channel_full(channel, band, WL_CHANSPEC_BW_20, 0);
}

int nex_set_channel_full(uint32 channel, uint32 band, uint32 bw,
                         uint32 ctl_sb) {
  char charbuf[13] = "chanspec";
  uint32 *chanspec = (uint32 *)&charbuf[9];

  *chanspec = (channel | band | bw | ctl_sb);
  // fprintf(stderr, "setting channel: channel=%08x   band=%08x   bw=%08x
  // ctl_sb=%08x  chanspec=%08x\n", channel, band, bw, ctl_sb, *chanspec);
  return nex_ioctl(nexio, WLC_SET_VAR, charbuf, 13, true);
}

int ioctl(int fd, request_t request, ...) {
  va_list args;
  void *argp;
  int ret;

  va_start(args, request);
  argp = va_arg(args, void *);
  va_end(args);

#if defined(ARCH_ARMHF)
  /* One request must not reach the driver at all.
   *
   * The S10 lane forwards first and fixes up afterwards, and on bcmdhd that is
   * harmless. On the watch it is not: the kernel answers SIOCSIWMODE by going
   * down into the firmware, and that write is what killed it — the same
   * redundant monitor re-enable Kismet's nl80211 path caused, arriving through
   * the legacy ioctl instead. Forwarding this call has nothing to contribute to
   * the result the handler below computes, and one thing to contribute to the
   * crash. Only our own interface is withheld; a call for any other interface is
   * not this library's business and is forwarded as before.
   *
   * SIOCSIFFLAGS clearing IFF_UP is the second request of that kind, and the
   * one that ends sessions from the outside: the netdev really goes down, the
   * Android framework reads isUp=false and tears its whole Wi-Fi stack down
   * around a radio that is still in use, and on the watch Wear OS then brings
   * Wi-Fi back on its own — "Wifi is OFF but mWifiDesired is TRUE ... reason:
   * ON_CHARGING" — re-initialising the dongle underneath the armed monitor
   * session. The observed reboots died there (dhd open -> CLM blob load ->
   * "SFR Init: wdog or kernel error suspected"). The tool only wants the
   * interface down so it can set monitor mode, and the radio is already armed,
   * so it gets the same honest answer the mode handler gives: success, radio
   * untouched. The up direction and every call for another interface are
   * forwarded as before, and NEXMON_ALLOW_IFDOWN=1 forwards even this one, for
   * a deliberate reset. */
  nex_ifdown_swallow = 0;
  if (argp != NULL && request == SIOCSIWMODE &&
      !strncmp(((struct iwreq *)argp)->ifr_ifrn.ifrn_name, ifname,
               strlen(ifname)))
    nex_ifdown_swallow = 1;
  else if (argp != NULL && request == SIOCSIFFLAGS &&
           !strncmp(((struct ifreq *)argp)->ifr_ifrn.ifrn_name, ifname,
                    strlen(ifname)) &&
           !(((struct ifreq *)argp)->ifr_flags & IFF_UP)) {
    const char *allow = getenv("NEXMON_ALLOW_IFDOWN");
    if (!(allow && allow[0] && allow[0] != '0')) {
      nex_ifdown_mon = 0;
      if (nexio)
        nex_ioctl(nexio, WLC_GET_MONITOR, &nex_ifdown_mon, 4, false);
      nex_ifdown_swallow = (nex_ifdown_mon != 0);
    }
  }
  if (nex_ifdown_swallow) {
    if (request == SIOCSIFFLAGS)
      nex_ifdown_fake++;
    ret = 0;
  } else
#endif
    ret = func_ioctl(fd, request, argp);
  // if (ret < 0) {
  //     fprintf(stderr, "LIBNEXMON: original response: %d, request: 0x%x\n",
  //     ret, request);
  // }

#if defined(ARCH_ARMHF)
  nex_ioctl_seen++;
#endif

  switch (request) {
  case SIOCGIFHWADDR: {
    int buf;
    struct ifreq *p_ifr = (struct ifreq *)argp;
    if (!strncmp(p_ifr->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);

      if (buf & MONITOR_IEEE80211)
        p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211;
      else if (buf & MONITOR_RADIOTAP)
        p_ifr->ifr_hwaddr.sa_family = ARPHRD_IEEE80211_RADIOTAP;
      else if (buf == MONITOR_DISABLED || (buf & MONITOR_LOG_ONLY) ||
               (buf & MONITOR_DROP_FRM) || (buf & MONITOR_IPV4_UDP))
        p_ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;

#if defined(ARCH_ARMHF)
      // This is the monitor-mode precondition, checked from the tool's side:
      // anything other than a radiotap/802.11 header type means the firmware
      // is not in monitor mode and wl_send_hook will not inject.
      nex_mon_get++;
      nex_dbgf("SIOCGIFHWADDR: firmware monitor state=0x%x -> reporting %s%s", buf,
               p_ifr->ifr_hwaddr.sa_family == ARPHRD_IEEE80211_RADIOTAP
                   ? "ARPHRD_IEEE80211_RADIOTAP (good)"
                   : p_ifr->ifr_hwaddr.sa_family == ARPHRD_IEEE80211
                         ? "ARPHRD_IEEE80211"
                         : "ARPHRD_ETHER",
               (p_ifr->ifr_hwaddr.sa_family == ARPHRD_ETHER)
                   ? " — NOT in monitor mode; run `nexutil -m2` first" : "");
#endif

      ret = 0;
    }
  } break;

  case SIOCGIWMODE: {
    int buf;
    struct iwreq *p_wrq = (struct iwreq *)argp;

    if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);

      if (buf & MONITOR_RADIOTAP || buf & MONITOR_IEEE80211 ||
          buf & MONITOR_LOG_ONLY || buf & MONITOR_DROP_FRM ||
          buf & MONITOR_IPV4_UDP) {
        p_wrq->u.mode = IW_MODE_MONITOR;

#if defined(ARCH_ARMHF)
        nex_mon_get++;
        nex_dbgf("SIOCGIWMODE: firmware monitor state=0x%x -> reporting IW_MODE_MONITOR", buf);
#endif

        // Passive enforcement for nexutil-based monitor mode (S10 BCM4375B1)
        // These settings are critical for handshake capture and WPS attacks
        // Errors are ignored to prevent "Operation Not Supported" issues
        int pm = 0; // CAM mode - prevents sleep, crucial for EAPOL/WPS frames
        nex_ioctl(nexio, WLC_SET_PM, &pm, 4, true);

        int promisc = 1; // Ensures we see all packets
        nex_ioctl(nexio, WLC_SET_PROMISC, &promisc, 4, true);
      }
#if defined(ARCH_ARMHF)
      else {
        nex_dbgf("SIOCGIWMODE: firmware monitor state=0x%x -> reporting "
                 "IW_MODE_MANAGED (no monitor mode set; `nexutil -m2` first)", buf);
      }
#endif

      ret = 0;
    }
#if defined(ARCH_ARMHF)
    else
      // Silence here used to be indistinguishable from the hook never being
      // entered. A tool asking about an interface we are not watching is a
      // different fault from a tool that never asked, and this says which.
      nex_dbgf("SIOCGIWMODE for \"%.*s\" ignored — this library watches \"%s\"",
               IFNAMSIZ, p_wrq->ifr_ifrn.ifrn_name, ifname);
#endif
  } break;

#if defined(ARCH_ARMHF)
  /* Not a hook — a marker. Bringing the interface up or down is one call, and
   * Kismet makes exactly this one twice per association attempt (its
   * ifconfig_interface_up() and ifconfig_interface_down() are a get and a set
   * of these flags). A tool that stops working after taking the interface down
   * has nothing to say for itself; this line says it instead. The up direction
   * is forwarded untouched, so nothing about the result changes. A down while
   * the radio is armed never reaches the driver at all — the pre-call gate
   * above answers it — and that is the one case worth saying out loud, because
   * it is the difference between a session that survives and one Android tears
   * down from underneath. */
  case SIOCSIFFLAGS: {
    struct ifreq *p_ifr = (struct ifreq *)argp;
    if (p_ifr && !strncmp(p_ifr->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      if (!(p_ifr->ifr_flags & IFF_UP) && nex_ifdown_swallow)
        nex_dbgf("SIOCSIFFLAGS: \"%.*s\" down requested with firmware monitor "
                 "state=0x%x — swallowed, the radio was left armed and the "
                 "framework never saw isUp=false (ret=%d)", IFNAMSIZ,
                 p_ifr->ifr_ifrn.ifrn_name, nex_ifdown_mon, ret);
      else
        nex_dbgf("SIOCSIFFLAGS: \"%.*s\" -> %s%s%s (ret=%d)", IFNAMSIZ,
                 p_ifr->ifr_ifrn.ifrn_name,
                 (p_ifr->ifr_flags & IFF_UP) ? "UP " : "down ",
                 (p_ifr->ifr_flags & IFF_PROMISC) ? "PROMISC " : "",
                 (p_ifr->ifr_flags & IFF_RUNNING) ? "RUNNING" : "", ret);
    }
  } break;
#endif

  case SIOCSIWMODE: {
    struct iwreq *p_wrq = (struct iwreq *)argp;

    if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
#if defined(ARCH_ARMHF)
      // Fired by every tool that uses the legacy path — airodump-ng,
      // aireplay-ng, reaver. This is usually the moment monitor mode goes on,
      // and on the watch that moment has already passed: the firmware was put
      // into monitor mode from Android before the tool started.
      //
      // So the request is answered from the firmware's own state and reported as
      // success without the radio being touched, in either direction. Acting on
      // it would be a redundant re-programming of a radio that is already in the
      // requested state — and the re-enable is the one that crashes the
      // firmware, which is the whole reason Kismet's nl80211 re-enable is faked
      // too. The disable direction is skipped for the same documented reason as
      // NL80211_IFTYPE_STATION: a tool that resets the interface partway through
      // startup would otherwise tear down the monitor mode you set.
      //
      // It cannot hide anything: SIOCGIFHWADDR above reports what the firmware
      // is really doing, so a tool that arrives before `nexutil -m2` is still
      // told the truth there, and this line says it again here.
      nex_mon_set++;
      {
        int mon = 0;
        nex_ioctl(nexio, WLC_GET_MONITOR, &mon, 4, false);
        nex_dbgf("SIOCSIWMODE: tool asks for mode %d (%s); firmware monitor "
                 "state=0x%x %s — radio left alone, reporting success",
                 p_wrq->u.mode,
                 p_wrq->u.mode == IW_MODE_MONITOR ? "monitor" : "not monitor",
                 mon, mon ? "" : "(NOT in monitor mode — run `nexutil -m2` first)");
      }
      return 0;
#else
      int buf;
      if (p_wrq->u.mode == IW_MODE_MONITOR) {
        buf = MONITOR_RADIOTAP;
        int promisc = 1;
        nex_ioctl(nexio, WLC_SET_PROMISC, &promisc, 4, true);
        int pm = 0; // Disable Power Management (CAM)
        nex_ioctl(nexio, WLC_SET_PM, &pm, 4, true);

        // For Kismet: Always return success even if the ioctl fails
        // Kismet uses this legacy path and will abort if it gets an error
        if (is_kismet) {
          nex_ioctl(nexio, WLC_SET_MONITOR, &buf, 4, true);
          return 0; // Force success for Kismet
        }
      } else {
        buf = MONITOR_DISABLED;
        // Restore radio to normal state so WiFi scanning/association works again
        // Without this, WLC_SET_SCANSUPPRESS=1 stays active → "no networks found"
        nex_restore_radio_defaults();
      }

      ret = nex_ioctl(nexio, WLC_SET_MONITOR, &buf, 4, true);
#endif // !ARCH_ARMHF — the watch answered this call and returned above
    }
#if defined(ARCH_ARMHF)
    else
      nex_dbgf("SIOCSIWMODE for \"%.*s\" ignored — this library watches \"%s\"",
               IFNAMSIZ, p_wrq->ifr_ifrn.ifrn_name, ifname);
#endif
  } break;

  case SIOCSIWFREQ: // set channel/frequency (Hz)
  {
    struct iwreq *p_wrq = (struct iwreq *)argp;

    if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      char charbuf[13] = "chanspec";
      uint32 *chanspec = (uint32 *)&charbuf[9];
      int channel = p_wrq->u.freq.m;
      int exp = p_wrq->u.freq.e;

      // TODO: test this!
      // fprintf(stderr, "SIWFREQ: chan/freq: m=%d e=%d\n", channel, exp);
      // if this is > 500 (or 1000, depending on the source), it's a frequency,
      // not a channel
      if (channel > 500 || exp > 0) {
        // convert from Hz to MHz
        if (exp < 6) {
          for (int i = 0; i < exp; i++)
            channel *= 10;
          channel /= 1000000;
        } else {
          for (int i = 6; i < exp; i++)
            channel *= 10;
        }
        // convert from frequency to channel
        channel = frequency_to_channel(channel);
      }

      // fprintf(stderr, "SIWFREQ: channel=%08x\n", channel);
#if defined(ARCH_ARMHF)
      /* The committed-association lane needs to know where the target is when
       * reaver -A supplies no auth/assoc frames to read it from. The channel
       * the tool tuned to is the best available answer; -c on the command line
       * is preferred over this if both are present. */
      nex_assoc_note_channel(channel);
#endif
      ret = nex_set_channel_simple(channel);

#if defined(ARCH_ARMHF)
      // Channel hopping is the other silent failure: if these stop landing,
      // airodump-ng sits on one channel and sees nothing while looking healthy.
      nex_chan_set++;
      nex_dbgf("SIOCSIWFREQ: hopping to channel %d -> ret=%d", channel, ret);
#endif

      // Enforce PM and Promisc after channel change
      // Changing channel can sometimes reset power save mode or promisc state
      // This ensures we stay awake and listening, preventing "Waiting for
      // beacon" hangs
      int pm = 0;
      nex_ioctl(nexio, WLC_SET_PM, &pm, 4, true);

      int promisc = 1;
      nex_ioctl(nexio, WLC_SET_PROMISC, &promisc, 4, true);
    }

    // if (ret < 0)
    // fprintf(stderr, "LIBNEXMON: SIOCSIWFREQ not fully implemented\n");
  } break;

  case SIOCGIWFREQ: // get channel/frequency (Hz)
  {
    struct iwreq *p_wrq = (struct iwreq *)argp;

    if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      char charbuf[9] = "chanspec";
      uint16 chanspec;
      int32 channel;
      ret = nex_ioctl(nexio, WLC_GET_VAR, charbuf, 9, false);
      if (ret >= 0) {
        chanspec = *(uint16 *)charbuf;
        channel = chanspec & 0xFF;
        p_wrq->u.freq.e = 0;
        p_wrq->u.freq.m = channel;
        // fprintf(stderr, "GIWFREQ: channel=%d\n", channel);
      }
    }

    // if (ret < 0)
    // fprintf(stderr, "LIBNEXMON: SIOCGIWFREQ not fully implemented\n");
  } break;

  case SIOCDEVPRIVATE: {
    // Intercept nexutil commands that go through SIOCDEVPRIVATE
    // nexutil -m0 uses this path: nex_ioctl → __nex_driver_io → ioctl(SIOCDEVPRIVATE)
    // We need to detect WLC_SET_MONITOR being set to 0 so we can restore radio defaults
    struct ifreq *p_ifr = (struct ifreq *)argp;
    if (p_ifr && p_ifr->ifr_data) {
      // struct nex_ioctl has .cmd as its first field (unsigned int)
      unsigned int cmd = *(unsigned int *)p_ifr->ifr_data;
      if (cmd == WLC_SET_MONITOR) {
        // Peek at the buffer to check if monitor is being disabled
        // nex_ioctl struct layout: { cmd, buf_ptr, len, set, ... }
        // We need to check if set==true and *buf==MONITOR_DISABLED
        struct {
          unsigned int cmd;
          void *buf;
          unsigned int len;
          bool set;
        } *ioc = (void *)p_ifr->ifr_data;
        
        if (ioc->set && ioc->buf && ioc->len >= 4) {
          int monitor_val = *(int *)ioc->buf;
          if (monitor_val == MONITOR_DISABLED) {
            // Monitor mode is being turned off (nexutil -m0)
            // Restore radio to normal state BEFORE the firmware processes it
            nex_restore_radio_defaults();
          }
#if defined(ARCH_ARMHF)
          // nexutil going through here is how the operator sets the
          // precondition by hand, so it is worth seeing what it asked for.
          nex_devpriv++;
          nex_dbgf("SIOCDEVPRIVATE: WLC_SET_MONITOR set=%d value=0x%x (%s)",
                   ioc->set, monitor_val,
                   monitor_val == MONITOR_DISABLED ? "monitor OFF"
                                                   : "monitor ON");
#endif
        }
      }
    }
    // Don't modify ret — it was already set by func_ioctl above
  } break;
  }
  return ret;
}

#if defined(ARCH_ARMHF) && defined(__TIMESIZE) && __TIMESIZE == 32
/* The name a tool calls is not always the name defined here.
 *
 * A 32-bit-time glibc hands callers the __*_time64 spelling of these entry
 * points as soon as they are built with _TIME_BITS=64, which is the armhf
 * default. The rename is an assembler label on the header's declaration, not a
 * macro, so it cannot be seen or undone with #ifdef — and it happens in the
 * tool's translation unit, not this one. Unless both spellings are exported,
 * the kernel takes the call and the firmware never sees it.
 *
 * That is the whole of the watch's "Error setting monitor mode on wlan0":
 * airodump-ng asks for the hardware type, gets the real ARPHRD_ETHER instead
 * of the fake above, concludes the interface is not in monitor mode, asks for
 * it, and the kernel answers EINVAL — while every ioctl counter reads zero,
 * because this hook was never entered at all.
 *
 * Two names, one address, one copy of the code. The alias names its own symbol
 * with __asm__ because a plain second declaration would simply inherit the
 * same label again. __TIMESIZE is a property of the target rather than of this
 * compile, so the pair is exported on every armhf build; a 64-bit host (the
 * test harness) has no rename to mirror and skips the block. */
int nex_ioctl_time64(int fd, request_t request, ...) __asm__("__ioctl_time64");
int nex_ioctl_time64(int fd, request_t request, ...)
    __attribute__((alias("ioctl")));
#endif

void hexdump(const char *desc, const void *addr, int len) {
  int i;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char *)addr;

  // Output description if given.
  if (desc != 0)
    printf("%s:\n", desc);

  // Process every byte in the data.
  for (i = 0; i < len; i++) {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0) {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)
        printf("  %s\n", buff);

      // Output the offset.
      printf("  %04x ", i);
    }

    // Now the hex code for the specific character.
    printf(" %02x", pc[i]);

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
      buff[i % 16] = '.';
    else
      buff[i % 16] = pc[i];
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0) {
    printf("   ");
    i++;
  }

  // And print the final ASCII bit.
  printf("  %s\n", buff);
}

static char sock_types[][16] = {
    "SOCK_STREAM", "SOCK_DGRAM", "SOCK_RAW", "SOCK_RDM", "SOCK_SEQPACKET",
};

static char domain_types[][16] = {
    "AF_UNSPEC",    "AF_UNIX",       "AF_INET",    "AF_AX25",    "AF_IPX",
    "AF_APPLETALK", "AF_NETROM",     "AF_BRIDGE",  "AF_ATMPVC",  "AF_X25",
    "AF_INET6",     "AF_ROSE",       "AF_DECnet",  "AF_NETBEUI", "AF_SECURITY",
    "AF_KEY",       "AF_NETLINK",    "AF_PACKET",  "AF_ASH",     "AF_ECONET",
    "AF_ATMSVC",    "AF_RDS",        "AF_SNA",     "AF_IRDA",    "AF_PPPOX",
    "AF_WANPIPE",   "AF_LLC",        "AF_IB",      "AF_MPLS",    "AF_CAN",
    "AF_TIPC",      "AF_BLUETOOTH",  "AF_IUCV",    "AF_RXRPC",   "AF_ISDN",
    "AF_PHONET",    "AF_IEEE802154", "AF_CAIF",    "AF_ALG",     "AF_NFC",
    "AF_VSOCK",     "AF_KCM",        "AF_QIPCRTR", "AF_SMC"};

#define MAX_TRACKED_FDS 4096
int socket_to_type[MAX_TRACKED_FDS] = {0};
char bound_to_correct_if[MAX_TRACKED_FDS] = {0};
char socket_is_netlink[MAX_TRACKED_FDS] = {0};  // Track netlink sockets for read() hook

int socket(int domain, int type, int protocol) {
  int ret;

  ret = func_socket(domain, type, protocol);

  // save the socket type
  if (ret > 0 && ret < (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    socket_to_type[ret] = type;
    // Track netlink sockets for the read() error suppression hook
    socket_is_netlink[ret] = (domain == AF_NETLINK) ? 1 : 0;
  }

#if defined(ARCH_ARMHF)
  if (ret > 0 && ret < (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    if (type == SOCK_RAW) {
      nex_sock_raw++;
      nex_dbgf("socket(domain=%d, SOCK_RAW, proto=%d) -> fd=%d  [now tracked for injection]",
               domain, protocol, ret);
    } else {
      nex_sock_other++;
    }
  }
#endif

  // if ((type - 1 < sizeof(sock_types)/sizeof(sock_types[0])) && (domain - 1 <
  // sizeof(domain_types)/sizeof(domain_types[0])))
  //     printf("LIBNEXMON: %d = %s(%s(%d), %s(%d), %d)\n", ret, __FUNCTION__,
  //     domain_types[domain], domain, sock_types[type - 1], type, protocol);

  return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int ret;
  struct sockaddr_ll *sll = (struct sockaddr_ll *)addr;

  ret = func_bind(sockfd, addr, addrlen);

  char sll_ifname[IF_NAMESIZE] = {0};
  if_indextoname(sll->sll_ifindex, sll_ifname);

  if ((sockfd > 0) &&
      (sockfd < (int)(sizeof(bound_to_correct_if) / sizeof(bound_to_correct_if[0]))) &&
      strcmp(ifname, sll_ifname) == 0)
    bound_to_correct_if[sockfd] = 1;

#if defined(ARCH_ARMHF)
  if ((sockfd > 0) &&
      (sockfd < (int)(sizeof(bound_to_correct_if) / sizeof(bound_to_correct_if[0])))) {
    if (bound_to_correct_if[sockfd]) {
      nex_bind_match++;
      nex_dbgf("bind(fd=%d) to %s — matches \"%s\", this socket can inject",
               sockfd, sll_ifname, ifname);
    } else if (socket_to_type[sockfd] == SOCK_RAW) {
      nex_bind_other++;
      nex_dbgf("bind(fd=%d) to %s — does NOT match \"%s\": this raw socket will "
               "never be treated as injection (NEXMON_IFACE overrides the name)",
               sockfd, sll_ifname, ifname);
    }
  }
#endif

  // printf("LIBNEXMON: %d = %s(%d, 0x%p, %d) sll_ifindex=%d ifname=%s\n", ret,
  // __FUNCTION__, sockfd, addr, addrlen, sll->sll_ifindex, sll_ifname);

  return ret;
}

struct inject_frame {
  unsigned short len;
  unsigned char pad;
  unsigned char type;
  char data[];
};

// Optimization: Thread-local static buffer to avoid malloc/free overhead per packet
// Max 802.11 frame size is ~2312 bytes, so 4096 is practically safe.
#define MAX_INJECT_BUF 4096
static __thread unsigned char _inject_buf_storage[MAX_INJECT_BUF];

#if defined(ARCH_ARMHF)
/* ── The committed association the watch's d11 ACK requires ────────────────
 *
 * Why this exists, in one paragraph. With monitor armed and no association,
 * the watch's radio never ACKs the AP's auth response, assoc response or EAPOL
 * frames. The AP therefore never commits the association and answers every
 * class-3 frame — the first EAPOL START included — with a deauth: reason 7
 * while it still believes we are authenticated, reason 23 once hostapd's EAP
 * session has failed. No userspace frame injection can produce the missing
 * ACK; it is a SIFS-time hardware job that only happens once the radio's
 * d11 has a committed association. The S10 does not have this problem because
 * its firmware ACKs injected frames itself, which is why `svc wifi disable`
 * was the right posture there and is the wrong one here: on the watch it
 * removes the one association that makes the ACK possible.
 *
 * What the shim does instead. On the wl_send_hook lane only, and only for the
 * tools whose whole job is a WPS exchange (reaver, bully — or any tool with
 * NEXMON_ASSOC_AUTO=1), it watches the frames the tool injects:
 *
 *   - an auth request names the target (Addr1);
 *   - an association request names the target and carries the SSID;
 *   - the first EAPOL frame is held until the association is committed.
 *
 * The association itself is the same NL80211_CMD_CONNECT that was proven on
 * the watch: the supplicant's 43-byte IE set (extended capabilities + WPS
 * enrollee IE + operating classes), and — the part that took a session to
 * find — the cipher/AKM attributes. Without those the driver logs
 * `sec=open/none` and the firmware refuses the join; with them it logs
 * `sec=wpa2psk/aes` and the link comes up.
 *
 * The EAPOL gate is what makes this race-free. Reaver sends EAPOL START
 * milliseconds after its own assoc response. If that frame left before the
 * driver's association committed, the AP would deauth the same MAC and tear
 * the new association down with it. Holding the first EAPOL frame for the
 * CONNECT event costs a second or two once per run and removes the race.
 *
 * For reaver -A (it injects no auth/assoc at all) the same target can be
 * given through NEXMON_ASSOC_BSSID / NEXMON_ASSOC_SSID / NEXMON_ASSOC_CHAN,
 * or read from the tool's own command line (-b, -c, -e) — the watch's reaver
 * is invoked with -b in every practical workflow.
 *
 * Nothing here is compiled for aarch64. The S10 lane is built byte for byte
 * as it shipped, and every symbol below is confined to this block.
 */

enum {
  NEX_ASSOC_IDLE = 0,
  NEX_ASSOC_CONNECTING,
  NEX_ASSOC_DONE,
  NEX_ASSOC_FAILED
};

#define NEX_ASSOC_SSID_MAX 32
#define NEX_ASSOC_TIMEOUT_MS 2500   /* how long a CONNECT gets to commit */
#define NEX_ASSOC_RETRY_MS 3000     /* pause between attempts, when one fails */
#define NEX_ASSOC_MAX_TRIES 4
#define NEX_ASSOC_BUF 1024
/* The nl80211 GETFAMILY reply on the watch is 2184 bytes (it carries every
 * multicast group the family has), so a 2048-byte buffer truncates the
 * datagram and the family id is never found. 8 KiB leaves room for any family
 * dump this code reads. */
#define NEX_ASSOC_RX_BUF 8192

/* The supplicant's own connect IE set, verbatim (43 bytes):
 *   extended capabilities (7f 0b) | WPS enrollee IE (dd 18) | op classes (3b 02)
 * No RSN IE: hostapd starts EAP-WSC instead of a 4-way handshake for a station
 * whose assoc request carries the WPS IE, and a WPS exchange is the whole point.
 */
static const unsigned char nex_assoc_ies[] = {
    0x7f, 0x0b, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x40, 0x40, 0x00, 0x00, 0x01,
    0x20, 0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10,
    0x10, 0x3a, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a,
    0x00, 0x01, 0x20, 0x3b, 0x02, 0x51, 0x51};
/* HT caps/mask = 0x0063 (26 bytes, first byte 0x63, rest zero); VHT zeroed. */
static const unsigned char nex_assoc_ht_cap[26] = {0x63};
static const unsigned char nex_assoc_vht_cap[12] = {0};

static unsigned char nex_assoc_ssid[NEX_ASSOC_SSID_MAX];
static size_t nex_assoc_ssid_len;
static unsigned char nex_assoc_bssid[6];
static int nex_assoc_have_bssid;
static int nex_assoc_chan;            /* last channel the tool tuned to */
static int nex_assoc_state = NEX_ASSOC_IDLE;
static int nex_assoc_tries;
static unsigned nex_assoc_next_try_ms;
static unsigned nex_assoc_deadline_ms;
static int nex_assoc_fd = -1;
static int nex_assoc_family;
static int nex_assoc_mlme;
static unsigned nex_assoc_seq;
static unsigned nex_assoc_connect_seq;
static int nex_assoc_last_errno;
static int nex_assoc_enabled_cache = -1;
static int nex_assoc_target_loaded;
static int nex_assoc_busy;
static int nex_assoc_note_printed;
static int nex_assoc_current_fd = -1;

static unsigned nex_assoc_now_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0;
  return (unsigned)((unsigned long long)ts.tv_sec * 1000 +
                    (unsigned long long)ts.tv_nsec / 1000000);
}

/* The channel the tool set through SIOCSIWFREQ or nl80211 SET_WIPHY. This
 * radio is 2.4 GHz only, so anything else is not a channel it can join. */
static void nex_assoc_note_channel(int channel) {
  if (channel >= 1 && channel <= 14)
    nex_assoc_chan = channel;
}

static unsigned nex_assoc_freq(void) {
  const char *e = getenv("NEXMON_ASSOC_FREQ");
  if (e && e[0]) {
    int f = atoi(e);
    if (f >= 2400 && f <= 2500)
      return (unsigned)f;
  }
  e = getenv("NEXMON_ASSOC_CHAN");
  if (e && e[0]) {
    int c = atoi(e);
    if (c >= 1 && c <= 14)
      return (unsigned)(c == 14 ? 2484 : 2412 + 5 * (c - 1));
  }
  if (nex_assoc_chan >= 1 && nex_assoc_chan <= 14)
    return (unsigned)(nex_assoc_chan == 14 ? 2484
                                           : 2412 + 5 * (nex_assoc_chan - 1));
  return 0;
}

static int nex_assoc_mac(const char *s, unsigned char out[6]) {
  unsigned v[6];
  int i;
  if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4],
                   &v[5]) != 6)
    return 0;
  for (i = 0; i < 6; i++)
    if (v[i] > 255)
      return 0;
  for (i = 0; i < 6; i++)
    out[i] = (unsigned char)v[i];
  return 1;
}

/* Target information: environment first, then the tool's own command line.
 * The command-line pass is what makes reaver -A work without extra setup: -b
 * names the AP and -c names the channel even though -A suppresses the frames
 * that would otherwise tell this library where to go. */
static void nex_assoc_load_target(void) {
  const char *env;
  char cl[1024];
  size_t n = 0;
  FILE *f;

  if (nex_assoc_target_loaded)
    return;
  nex_assoc_target_loaded = 1;

  env = getenv("NEXMON_ASSOC_SSID");
  if (env) {
    size_t len = strlen(env);
    if (len > NEX_ASSOC_SSID_MAX)
      len = NEX_ASSOC_SSID_MAX;
    memcpy(nex_assoc_ssid, env, len);
    nex_assoc_ssid_len = len;
  }
  env = getenv("NEXMON_ASSOC_BSSID");
  if (env && nex_assoc_mac(env, nex_assoc_bssid))
    nex_assoc_have_bssid = 1;

  f = fopen("/proc/self/cmdline", "r");
  if (f) {
    n = fread(cl, 1, sizeof(cl) - 1, f);
    fclose(f);
  }
  cl[n] = 0;

  {
    char *args[64];
    int argc = 0, i;
    char *p = cl, *end = cl + n;
    while (p < end && argc < 64) {
      args[argc++] = p;
      p += strlen(p) + 1;
    }
    for (i = 0; i < argc; i++) {
      const char *a = args[i];
      const char *val = NULL;

      /* -b / --bssid */
      if (!strcmp(a, "-b") || !strcmp(a, "--bssid"))
        val = (i + 1 < argc) ? args[i + 1] : NULL;
      else if (!strncmp(a, "--bssid=", 8))
        val = a + 8;
      else if (a[0] == '-' && a[1] == 'b' && a[2])
        val = a + 2;
      if (val && !nex_assoc_have_bssid && nex_assoc_mac(val, nex_assoc_bssid))
        nex_assoc_have_bssid = 1;

      /* -c / --channel */
      val = NULL;
      if (!strcmp(a, "-c") || !strcmp(a, "--channel"))
        val = (i + 1 < argc) ? args[i + 1] : NULL;
      else if (!strncmp(a, "--channel=", 10))
        val = a + 10;
      else if (a[0] == '-' && a[1] == 'c' && a[2])
        val = a + 2;
      if (val && !nex_assoc_chan) {
        int c = atoi(val);
        if (c >= 1 && c <= 14)
          nex_assoc_chan = c;
      }

      /* -e / --ssid */
      val = NULL;
      if (!strcmp(a, "-e") || !strcmp(a, "--ssid"))
        val = (i + 1 < argc) ? args[i + 1] : NULL;
      else if (!strncmp(a, "--ssid=", 7))
        val = a + 7;
      else if (a[0] == '-' && a[1] == 'e' && a[2])
        val = a + 2;
      if (val && nex_assoc_ssid_len == 0) {
        size_t len = strlen(val);
        if (len > NEX_ASSOC_SSID_MAX)
          len = NEX_ASSOC_SSID_MAX;
        memcpy(nex_assoc_ssid, val, len);
        nex_assoc_ssid_len = len;
      }
    }
  }
}

/* The lane is for the WPS tools by default. Kismet is passive and the rest of
 * the aircrack-ng suite (airodump, aireplay, hcxdumptool) must keep the
 * behaviour they had; NEXMON_ASSOC_AUTO=1 opts any tool in, =0 opts reaver out. */
static int nex_assoc_enabled(void) {
  if (nex_assoc_enabled_cache >= 0)
    return nex_assoc_enabled_cache;

  {
    const char *e = getenv("NEXMON_ASSOC_AUTO");
    if (e && e[0]) {
      nex_assoc_enabled_cache = (e[0] != '0');
    } else {
      char proc[64];
      nex_proc_name(proc, sizeof(proc));
      nex_assoc_enabled_cache =
          (strstr(proc, "reaver") || strstr(proc, "bully")) ? 1 : 0;
    }
  }

  if (nex_assoc_enabled_cache) {
    nex_assoc_load_target();
    nex_dbgf("association: lane enabled (target bssid %s, ssid \"%.*s\", "
             "channel %d from %s)", nex_assoc_have_bssid ? "known" : "not yet",
             (int)nex_assoc_ssid_len, (const char *)nex_assoc_ssid,
             nex_assoc_chan, nex_assoc_chan ? "the tool" : "nowhere yet");
  }
  return nex_assoc_enabled_cache;
}

/* Is the interface associated, and to whom? SIOCGIWAP is the wext getter the
 * watch's bcmdhd answers (verified on the device); the zero MAC means no
 * association. This is how the lane tells "already committed, leave it alone"
 * from "associated to some other AP, the target needs the radio". */
static int nex_assoc_current_bssid(unsigned char out[6]) {
  struct iwreq wrq;
  int i;

  if (!func_ioctl || !func_socket)
    return 0;
  if (nex_assoc_current_fd < 0)
    nex_assoc_current_fd = func_socket(AF_INET, SOCK_DGRAM, 0);
  if (nex_assoc_current_fd < 0)
    return 0;

  memset(&wrq, 0, sizeof(wrq));
  snprintf(wrq.ifr_ifrn.ifrn_name, IFNAMSIZ, "%s", ifname);
  if (func_ioctl(nex_assoc_current_fd, SIOCGIWAP, &wrq) < 0)
    return 0;
  if (wrq.u.ap_addr.sa_family != ARPHRD_ETHER)
    return 0;
  memcpy(out, wrq.u.ap_addr.sa_data, 6);
  for (i = 0; i < 6; i++)
    if (out[i])
      return 1;
  return 0;                        /* all-zero address: not associated */
}

static void nex_assoc_put16(unsigned char *p, unsigned v) {
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
}

static void nex_assoc_put32(unsigned char *p, unsigned v) {
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

static unsigned nex_assoc_get16(const unsigned char *p) {
  return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned nex_assoc_get32(const unsigned char *p) {
  return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) |
         ((unsigned)p[3] << 24);
}

/* Generic-netlink attribute: header, payload, four-byte alignment. */
static int nex_assoc_attr(unsigned char *buf, size_t cap, size_t *off,
                          unsigned short type, const void *data, size_t len) {
  size_t alen = 4 + len;
  size_t padded = (alen + 3) & ~(size_t)3;
  if (*off + padded > cap)
    return -1;
  nex_assoc_put16(buf + *off, (unsigned)alen);
  nex_assoc_put16(buf + *off + 2, type);
  if (len)
    memcpy(buf + *off + 4, data, len);
  if (padded > alen)
    memset(buf + *off + alen, 0, padded - alen);
  *off += padded;
  return 0;
}

static int nex_assoc_attr_u32(unsigned char *buf, size_t cap, size_t *off,
                              unsigned short type, unsigned value) {
  unsigned char v[4];
  nex_assoc_put32(v, value);
  return nex_assoc_attr(buf, cap, off, type, v, 4);
}

static int nex_assoc_find(const unsigned char *buf, size_t start, size_t end,
                          unsigned short type, const unsigned char **out,
                          size_t *out_len) {
  size_t off = start;
  while (off + 4 <= end) {
    unsigned alen = nex_assoc_get16(buf + off);
    unsigned atype = nex_assoc_get16(buf + off + 2);
    if (alen < 4 || off + alen > end)
      break;
    if (atype == type) {
      *out = buf + off + 4;
      *out_len = alen - 4;
      return 1;
    }
    off += (alen + 3) & ~(size_t)3;
  }
  return 0;
}

/* Send one generic-netlink request on the association socket. Bypasses the
 * send hook on purpose: this is the shim's own traffic, not the tool's, and it
 * must never be classified as frame injection. */
static int nex_assoc_send(unsigned short nltype, unsigned char genl_cmd,
                          const unsigned char *attrs, size_t alen,
                          unsigned *seq_out) {
  unsigned char buf[NEX_ASSOC_BUF];
  struct sockaddr_nl kaddr;
  size_t total;
  unsigned seq;
  int n;

  if (nex_assoc_fd < 0 || alen + 20 > sizeof(buf))
    return -1;

  total = 20 + alen;
  seq = ++nex_assoc_seq;
  nex_assoc_put32(buf + 0, (unsigned)total);      /* nlmsg_len */
  nex_assoc_put16(buf + 4, nltype);               /* nlmsg_type */
  nex_assoc_put16(buf + 6, NLM_F_REQUEST | NLM_F_ACK);
  nex_assoc_put32(buf + 8, seq);                  /* nlmsg_seq */
  nex_assoc_put32(buf + 12, 0);                   /* nlmsg_pid */
  buf[16] = genl_cmd;                             /* genlmsghdr */
  buf[17] = 1;                                    /* version */
  nex_assoc_put16(buf + 18, 0);
  if (alen)
    memcpy(buf + 20, attrs, alen);

  memset(&kaddr, 0, sizeof(kaddr));
  kaddr.nl_family = AF_NETLINK;
  n = func_sendto(nex_assoc_fd, buf, total, 0, (struct sockaddr *)&kaddr,
                  sizeof(kaddr));
  if (n < 0)
    return -1;
  if (seq_out)
    *seq_out = seq;
  return 0;
}

/* Resolve the nl80211 family id and the mlme multicast group from the
 * controller — never hardcoded: the family id on this watch is 19 and the mlme
 * group is 5, but both are kernel-assigned. */
static int nex_assoc_family_lookup(void) {
  unsigned char attrs[64];
  unsigned char rx[NEX_ASSOC_RX_BUF];
  size_t alen = 0;
  unsigned deadline;

  if (nex_assoc_attr(attrs, sizeof(attrs), &alen, CTRL_ATTR_FAMILY_NAME,
                     "nl80211", 8) < 0)   /* the trailing NUL is required */
    return 0;
  if (nex_assoc_send(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, attrs, alen, NULL) < 0) {
    nex_dbgf("association: GETFAMILY send failed: %s", strerror(errno));
    return 0;
  }

  nex_assoc_family = 0;
  nex_assoc_mlme = 0;
  deadline = nex_assoc_now_ms() + 1000;
  while ((int)(deadline - nex_assoc_now_ms()) > 0) {
    struct pollfd p;
    int wait = (int)(deadline - nex_assoc_now_ms());
    int r;
    ssize_t n;
    if (wait < 0)
      wait = 0;
    if (wait > 200)
      wait = 200;
    p.fd = nex_assoc_fd;
    p.events = POLLIN;
    p.revents = 0;
    r = poll(&p, 1, wait);
    if (r <= 0)
      continue;
    n = func_read(nex_assoc_fd, rx, sizeof(rx));
    if (n <= 0)
      continue;
    if ((size_t)n >= sizeof(rx) && nex_assoc_get32(rx) > (size_t)n) {
      nex_dbgf("association: netlink reply truncated (%u bytes declared, "
               "%zu received) — buffer too small", nex_assoc_get32(rx),
               (size_t)n);
      continue;
    }

    {
      size_t off = 0;
      while (off + 16 <= (size_t)n) {
        unsigned len = nex_assoc_get32(rx + off);
        unsigned short type = (unsigned short)nex_assoc_get16(rx + off + 4);
        if (len < 16 || off + len > (size_t)n)
          break;
        if (type == GENL_ID_CTRL && len >= 20) {
          const unsigned char *v;
          size_t vl;
          if (nex_assoc_find(rx, off + 20, off + len, CTRL_ATTR_FAMILY_ID, &v,
                             &vl) && vl >= 2)
            nex_assoc_family = (int)nex_assoc_get16(v);
          if (nex_assoc_find(rx, off + 20, off + len,
                             CTRL_ATTR_MCAST_GROUPS, &v, &vl)) {
            size_t goff = 0;
            while (goff + 4 <= vl) {
              unsigned glen = nex_assoc_get16(v + goff);
              size_t gend = goff + glen;
              const unsigned char *name, *id;
              size_t nlen, ilen;
              if (glen < 4 || gend > vl)
                break;
              if (nex_assoc_find(v, goff + 4, gend, CTRL_ATTR_MCAST_GRP_NAME,
                                 &name, &nlen) &&
                  nex_assoc_find(v, goff + 4, gend, CTRL_ATTR_MCAST_GRP_ID,
                                 &id, &ilen) &&
                  ilen >= 4 && nlen >= 4 && !memcmp(name, "mlme", 4) &&
                  (nlen == 4 || name[4] == 0))
                nex_assoc_mlme = (int)nex_assoc_get32(id);
              goff = (gend + 3) & ~(size_t)3;
            }
          }
        }
        off += (len + 3) & ~(size_t)3;
      }
    }
    if (nex_assoc_family > 0)
      return 1;
  }
  return 0;
}

static int nex_assoc_open(void) {
  struct sockaddr_nl sa;
  int fd;

  if (nex_assoc_fd >= 0)
    return 1;
  if (!func_socket || !func_bind || !func_sendto || !func_read || !func_ioctl) {
    nex_dbgf("association: netlink unavailable — a syscall pointer is missing "
             "(socket=%p bind=%p sendto=%p read=%p ioctl=%p)", (void *)func_socket,
             (void *)func_bind, (void *)func_sendto, (void *)func_read,
             (void *)func_ioctl);
    return 0;
  }

  fd = func_socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
  if (fd < 0) {
    nex_dbgf("association: netlink socket(AF_NETLINK, SOCK_RAW, %d) failed: "
             "%s", NETLINK_GENERIC, strerror(errno));
    return 0;
  }

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (func_bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    nex_dbgf("association: netlink bind failed: %s", strerror(errno));
    close(fd);
    return 0;
  }
  nex_assoc_fd = fd;

  if (!nex_assoc_family_lookup() || nex_assoc_mlme <= 0) {
    nex_dbgf("association: nl80211 family lookup failed (family=%d mlme=%d): %s",
             nex_assoc_family, nex_assoc_mlme, strerror(errno));
    close(nex_assoc_fd);
    nex_assoc_fd = -1;
    return 0;
  }

  {
    static int (*real_setsockopt)(int, int, int, const void *, socklen_t);
    int group = nex_assoc_mlme;
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif
    if (!real_setsockopt)
      real_setsockopt = (int (*)(int, int, int, const void *, socklen_t))dlsym(
          REAL_LIBC, "setsockopt");
    if (!real_setsockopt) {
      nex_dbgf("association: dlsym(RTLD_NEXT, setsockopt) returned NULL");
      close(fd);
      nex_assoc_fd = -1;
      return 0;
    }
    if (real_setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group,
                        sizeof(group)) < 0) {
      nex_dbgf("association: subscribe to mlme group %d failed "
               "(SOL_NETLINK=%d): %s", group, SOL_NETLINK, strerror(errno));
      close(fd);
      nex_assoc_fd = -1;
      return 0;
    }
  }

  nex_dbgf("association: generic netlink ready (nl80211 family=%d, mlme "
           "group=%d, subscribed)", nex_assoc_family, nex_assoc_mlme);
  return 1;
}

/* Drain whatever the association socket has queued, stopping after quiet_ms of
 * silence. Used to throw away a previous DISCONNECT's own event before a new
 * CONNECT is sent, so a stale event can never be mistaken for a fresh deauth. */
static void nex_assoc_drain(int quiet_ms) {
  unsigned char rx[NEX_ASSOC_RX_BUF];
  for (;;) {
    struct pollfd p;
    p.fd = nex_assoc_fd;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, quiet_ms) <= 0)
      return;
    if (func_read(nex_assoc_fd, rx, sizeof(rx)) <= 0)
      return;
  }
}

static int nex_assoc_wait_ack(unsigned seq, int ms) {
  unsigned char rx[NEX_ASSOC_RX_BUF];
  unsigned deadline = nex_assoc_now_ms() + (unsigned)ms;
  while ((int)(deadline - nex_assoc_now_ms()) > 0) {
    struct pollfd p;
    int wait = (int)(deadline - nex_assoc_now_ms());
    ssize_t n;
    if (wait < 0)
      wait = 0;
    if (wait > 150)
      wait = 150;
    p.fd = nex_assoc_fd;
    p.events = POLLIN;
    p.revents = 0;
    if (poll(&p, 1, wait) <= 0)
      continue;
    n = func_read(nex_assoc_fd, rx, sizeof(rx));
    if (n <= 0)
      continue;
    {
      size_t off = 0;
      while (off + 16 <= (size_t)n) {
        unsigned len = nex_assoc_get32(rx + off);
        unsigned short type = (unsigned short)nex_assoc_get16(rx + off + 4);
        if (len < 16 || off + len > (size_t)n)
          break;
        if (type == NLMSG_ERROR && len >= 20 &&
            nex_assoc_get32(rx + off + 8) == seq)
          return 1;                /* the ACK (or the error) for our request */
        off += (len + 3) & ~(size_t)3;
      }
    }
  }
  return 0;
}

/* One netlink message from the association socket. Returns 1 on a committed
 * connect, 2 when the kernel says the interface is already connected or
 * connecting (which is just as good for the ACK's purpose), -1 on a failure
 * that is worth reporting, and 0 when this message was not the result. */
static int nex_assoc_handle(const unsigned char *buf, ssize_t n) {
  size_t off = 0;
  while (off + 16 <= (size_t)n) {
    unsigned len = nex_assoc_get32(buf + off);
    unsigned type = nex_assoc_get16(buf + off + 4);
    unsigned seq = nex_assoc_get32(buf + off + 8);
    if (len < 16 || off + len > (size_t)n)
      break;

    if (type == NLMSG_ERROR && len >= 20) {
      int err;
      memcpy(&err, buf + off + 16, 4);
      if (err != 0 && seq == nex_assoc_connect_seq) {
        nex_assoc_last_errno = -err;
        nex_dbgf("association: CONNECT refused by the kernel: %d (%s)", err,
                 strerror(-err));
        return (-err == EALREADY) ? 2 : -1;
      }
    } else if (type == (unsigned)nex_assoc_family && len >= 20) {
      unsigned char cmd = buf[off + 16];
      if (cmd == NL80211_CMD_CONNECT) {
        const unsigned char *v;
        size_t vl;
        unsigned status = 0;
        if (nex_assoc_find(buf, off + 20, off + len,
                           NL80211_ATTR_STATUS_CODE, &v, &vl) && vl >= 2)
          status = nex_assoc_get16(v);
        if (status == 0)
          return 1;
        nex_assoc_last_errno = 0;
        nex_dbgf("association: CONNECT result status=%u", status);
        return -1;
      }
      if (cmd == NL80211_CMD_DISCONNECT) {
        const unsigned char *v;
        size_t vl;
        unsigned reason = 0;
        if (nex_assoc_find(buf, off + 20, off + len, NL80211_ATTR_REASON_CODE,
                           &v, &vl) && vl >= 2)
          reason = nex_assoc_get16(v);
        nex_assoc_last_errno = 0;
        nex_dbgf("association: DISCONNECT event (reason %u) while waiting for "
                 "the connect to commit", reason);
        return -1;
      }
    }
    off += (len + 3) & ~(size_t)3;
  }
  return 0;
}

/* Wait for the CONNECT result, bounded by the deadline set when the request
 * was sent. The tool's own transmitter is blocked for the duration — that is
 * the point: the first EAPOL frame must not leave before the d11 can ACK. */
static int nex_assoc_wait(void) {
  unsigned char rx[NEX_ASSOC_RX_BUF];
  while ((int)(nex_assoc_deadline_ms - nex_assoc_now_ms()) > 0) {
    struct pollfd p;
    int wait = (int)(nex_assoc_deadline_ms - nex_assoc_now_ms());
    int r;
    ssize_t n;
    if (wait < 0)
      wait = 0;
    if (wait > 250)
      wait = 250;
    p.fd = nex_assoc_fd;
    p.events = POLLIN;
    p.revents = 0;
    r = poll(&p, 1, wait);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (r == 0)
      continue;
    n = func_read(nex_assoc_fd, rx, sizeof(rx));
    if (n <= 0)
      continue;
    r = nex_assoc_handle(rx, n);
    if (r != 0)
      return r;
  }
  nex_assoc_last_errno = ETIMEDOUT;
  return -1;
}

static void nex_assoc_disconnect(void) {
  unsigned char attrs[32];
  size_t alen = 0;
  unsigned seq = 0;

  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_IFINDEX,
                     if_nametoindex(ifname));
  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_REASON_CODE, 3);
  if (nex_assoc_send((unsigned short)nex_assoc_family, NL80211_CMD_DISCONNECT,
                     attrs, alen, &seq) == 0)
    nex_assoc_wait_ack(seq, 600);
  /* The kernel may emit the matching DISCONNECT event as well; make sure it is
   * consumed before a CONNECT is sent, or the wait would read it as a deauth. */
  nex_assoc_drain(60);
}

/* A frame the tool injects only reaches the air on the channel the firmware is
 * actually working. While the interface is associated to some other AP, the
 * firmware's channel context belongs to that link; a default reaver run then
 * shows exactly the loop seen on the watch — "Sending authentication request"
 * followed by "Receive timeout" forever, because the auth request never left
 * channel 6 for channel 11. Releasing the foreign association (and
 * re-asserting the channel the tool asked for) gives the tool's own frames the
 * air. The committed CONNECT later in the exchange then builds the association
 * the d11 must keep — under the same MAC, so the AP sees one station. */
static void nex_assoc_release_radio(void) {
  unsigned char cur[6];
  char old[24];
  unsigned freq;
  int chan = 0;

  if (nex_assoc_busy)
    return;
  if (nex_assoc_state == NEX_ASSOC_CONNECTING)
    return;                          /* never cancel our own connect */
  if (!nex_assoc_have_bssid || !nex_assoc_current_bssid(cur))
    return;
  if (!memcmp(cur, nex_assoc_bssid, 6))
    return;                          /* already on the target; TX can leave */
  if (!nex_assoc_open())
    return;

  snprintf(old, sizeof(old), "%02x:%02x:%02x:%02x:%02x:%02x", cur[0], cur[1],
           cur[2], cur[3], cur[4], cur[5]);
  freq = nex_assoc_freq();
  if (freq >= 2412 && freq <= 2472)
    chan = (int)((freq - 2407) / 5);
  else if (freq == 2484)
    chan = 14;

  nex_assoc_busy = 1;
  nex_dbgf("association: the radio is associated to %s, so frames injected "
           "for the target cannot leave on channel %d; releasing that "
           "association first", old, chan ? chan : nex_assoc_chan);
  nex_assoc_disconnect();
  if (chan) {
    int ret = nex_set_channel_full((uint32)chan, WL_CHANSPEC_BAND_2G,
                                   WL_CHANSPEC_BW_20, 0);
    nex_dbgf("association: re-tuned to channel %d -> ret=%d", chan, ret);
  }
  nex_assoc_state = NEX_ASSOC_IDLE;  /* the assoc request builds the link */
  nex_assoc_tries = 0;
  nex_assoc_busy = 0;
}

/* Issue the proven CONNECT. Returns 1 when a request is in flight, 2 when the
 * interface is already associated to the target, 0 when nothing could start. */
static int nex_assoc_start(void) {
  unsigned char attrs[512];
  unsigned char cur[6];
  unsigned char suite[4];
  size_t alen = 0;
  unsigned seq = 0;
  unsigned freq;
  char mac[24];

  if (nex_assoc_busy)
    return 0;
  if (nex_assoc_state == NEX_ASSOC_DONE)
    return 2;
  if (!nex_assoc_have_bssid || !(freq = nex_assoc_freq()))
    return 0;

  nex_assoc_kick_n++;
  snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
           nex_assoc_bssid[0], nex_assoc_bssid[1], nex_assoc_bssid[2],
           nex_assoc_bssid[3], nex_assoc_bssid[4], nex_assoc_bssid[5]);

  /* Already associated to this exact AP: the d11 is already ACKing. No
   * CONNECT and no netlink socket needed — tearing a working association down
   * to rebuild it would only add a hostapd state transition the exchange does
   * not need. Checked before opening anything so this common case (the watch
   * is on the home AP and reaver is aimed at the same AP) costs nothing and
   * cannot be reported as a failed attempt. */
  if (nex_assoc_current_bssid(cur) &&
      !memcmp(cur, nex_assoc_bssid, 6)) {
    nex_assoc_state = NEX_ASSOC_DONE;
    nex_assoc_ok_n++;
    nex_dbgf("association: already associated to %s — the radio is already "
             "ACKing; leaving the link untouched", mac);
    return 2;
  }

  if (!nex_assoc_open()) {
    nex_assoc_fail_n++;
    nex_assoc_tries++;
    nex_assoc_next_try_ms = nex_assoc_now_ms() + NEX_ASSOC_RETRY_MS;
    nex_assoc_state = NEX_ASSOC_FAILED;
    nex_dbgf("association: could not open the generic-netlink socket — the "
             "frame will go out without a committed association");
    return 0;
  }

  nex_assoc_busy = 1;
  /* Associated to some other AP: the target needs the radio, so clear the old
   * link. This is the one case where the lane deliberately changes an
   * association, and it is logged. */
  if (nex_assoc_current_bssid(cur)) {
    char old[24];
    snprintf(old, sizeof(old), "%02x:%02x:%02x:%02x:%02x:%02x", cur[0],
             cur[1], cur[2], cur[3], cur[4], cur[5]);
    nex_dbgf("association: interface is associated to %s, not the target %s — "
             "disconnecting so the target can be joined", old, mac);
    nex_assoc_disconnect();
  } else {
    nex_assoc_drain(20);
  }

  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_IFINDEX,
                     if_nametoindex(ifname));
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_SSID,
                 nex_assoc_ssid, nex_assoc_ssid_len);
  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_WIPHY_FREQ,
                     freq);
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_MAC,
                 nex_assoc_bssid, 6);
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_IE,
                 nex_assoc_ies, sizeof(nex_assoc_ies));
  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_AUTH_TYPE, 0);

  /* The attributes without which the driver logs sec=open/none and the
   * firmware refuses the join. Pairwise and AKM are arrays of u32 in host
   * byte order; CCMP is 00:0f:ac:04, PSK is 00:0f:ac:02. */
  nex_assoc_put32(suite, 0x000fac04);
  nex_assoc_attr(attrs, sizeof(attrs), &alen,
                 NL80211_ATTR_CIPHER_SUITES_PAIRWISE, suite, 4);
  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen,
                     NL80211_ATTR_CIPHER_SUITE_GROUP, 0x000fac04);
  nex_assoc_attr_u32(attrs, sizeof(attrs), &alen, NL80211_ATTR_WPA_VERSIONS,
                     2);
  nex_assoc_put32(suite, 0x000fac02);
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_AKM_SUITES, suite,
                 4);

  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_HT_CAPABILITY,
                 nex_assoc_ht_cap, sizeof(nex_assoc_ht_cap));
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_HT_CAPABILITY_MASK,
                 nex_assoc_ht_cap, sizeof(nex_assoc_ht_cap));
  nex_assoc_attr(attrs, sizeof(attrs), &alen, NL80211_ATTR_VHT_CAPABILITY,
                 nex_assoc_vht_cap, sizeof(nex_assoc_vht_cap));
  nex_assoc_attr(attrs, sizeof(attrs), &alen,
                 NL80211_ATTR_VHT_CAPABILITY_MASK, nex_assoc_vht_cap,
                 sizeof(nex_assoc_vht_cap));

  if (nex_assoc_send((unsigned short)nex_assoc_family, NL80211_CMD_CONNECT,
                     attrs, alen, &seq) < 0) {
    nex_assoc_fail_n++;
    nex_assoc_tries++;
    nex_assoc_next_try_ms = nex_assoc_now_ms() + NEX_ASSOC_RETRY_MS;
    nex_assoc_state = NEX_ASSOC_FAILED;
    nex_dbgf("association: CONNECT could not be sent (%s)", strerror(errno));
    nex_assoc_busy = 0;
    return 0;
  }

  nex_assoc_connect_seq = seq;
  nex_assoc_deadline_ms = nex_assoc_now_ms() + NEX_ASSOC_TIMEOUT_MS;
  nex_assoc_state = NEX_ASSOC_CONNECTING;
  nex_dbgf("association: CONNECT issued for %s (ssid \"%.*s\", %u MHz, "
           "WPA2-PSK/CCMP + WPS IE) — the next EAPOL frame waits for it",
           mac, (int)nex_assoc_ssid_len, (const char *)nex_assoc_ssid, freq);
  nex_assoc_busy = 0;
  return 1;
}

/* Called for the first EAPOL frame (and every retry). Holds the frame until
 * the association commits, because the frame cannot be ACKed without one. */
static void nex_assoc_gate(void) {
  unsigned char cur[6];
  int r;

  if (!nex_assoc_have_bssid || !nex_assoc_freq()) {
    if (!nex_assoc_note_printed) {
      nex_assoc_note_printed = 1;
      nex_dbgf("association: an EAPOL frame is ready but no target is known — "
               "run reaver without -A (its assoc request names the AP), or set "
               "NEXMON_ASSOC_BSSID and NEXMON_ASSOC_CHAN/NEXMON_ASSOC_SSID");
    }
    return;
  }

  if (nex_assoc_state == NEX_ASSOC_DONE) {
    if (nex_assoc_current_bssid(cur) && !memcmp(cur, nex_assoc_bssid, 6))
      return;                       /* still committed */
    nex_dbgf("association: the link to the target is gone (a deauth or a "
             "disconnect); establishing it again before this EAPOL frame");
    nex_assoc_state = NEX_ASSOC_IDLE;
    nex_assoc_tries = 0;
  }

  if (nex_assoc_state == NEX_ASSOC_FAILED) {
    if (nex_assoc_tries >= NEX_ASSOC_MAX_TRIES ||
        (int)(nex_assoc_next_try_ms - nex_assoc_now_ms()) > 0)
      return;                       /* let it out; a later retry may succeed */
    nex_assoc_state = NEX_ASSOC_IDLE;
  }

  if (nex_assoc_state == NEX_ASSOC_IDLE) {
    r = nex_assoc_start();
    if (r == 0)
      return;                       /* failure already recorded by start() */
  }

  if (nex_assoc_state != NEX_ASSOC_CONNECTING)
    return;

  nex_assoc_gate_n++;
  r = nex_assoc_wait();
  if (r > 0) {
    nex_assoc_state = NEX_ASSOC_DONE;
    nex_assoc_ok_n++;
    nex_assoc_tries = 0;
    if (r == 2)
      nex_dbgf("association: kernel reports already connected/connecting — "
               "the d11 has an association; releasing the EAPOL frame");
    else
      nex_dbgf("association: CONNECT committed — the d11 can ACK now; "
               "releasing the EAPOL frame");
  } else {
    nex_assoc_fail_n++;
    nex_assoc_tries++;
    nex_assoc_next_try_ms = nex_assoc_now_ms() + NEX_ASSOC_RETRY_MS;
    nex_assoc_state = NEX_ASSOC_FAILED;
    nex_dbgf("association: the connect did not commit (%s) — the EAPOL frame "
             "is released anyway, and a later retry may still succeed",
             nex_assoc_last_errno ? strerror(nex_assoc_last_errno)
                                  : "no CONNECT event");
  }
}

/* Frames the tool injects. Only the wl_send_hook lane can be helped here; on
 * the ioctl lane the firmware does its own association and this must stay out
 * of the way. */
static void nex_assoc_observe_tx(const unsigned char *f, size_t flen) {
  unsigned type, st;

  if (!nex_assoc_enabled())
    return;
  if (current_inject_method != INJECT_RAW_SOCKET)
    return;
  if (flen < 2)
    return;

  type = (f[0] >> 2) & 0x3;
  st = (f[0] >> 4) & 0xf;

  if (type == 0) {
    if (st == 11 && flen >= 28 && nex_le16(f + 26) == 1) {
      /* Auth request: names the AP. The SSID comes with the assoc request. */
      if (!nex_assoc_have_bssid) {
        memcpy(nex_assoc_bssid, f + 4, 6);
        nex_assoc_have_bssid = 1;
      }
      /* If the radio is holding some other AP's association, this frame
       * cannot leave on the target's channel; free it first. */
      nex_assoc_release_radio();
      return;
    }
    if (st == 0 || st == 2) {
      size_t off = 24 + (st == 2 ? 10 : 4);
      if (flen >= 24) {
        /* The assoc request is authoritative about who is being joined. */
        memcpy(nex_assoc_bssid, f + 4, 6);
        nex_assoc_have_bssid = 1;
      }
      while (off + 2 <= flen) {
        unsigned id = f[off];
        unsigned elen = f[off + 1];
        if (off + 2 + elen > flen)
          break;
        if (id == 0 && elen <= NEX_ASSOC_SSID_MAX) {
          memcpy(nex_assoc_ssid, f + off + 2, elen);
          nex_assoc_ssid_len = elen;
          break;
        }
        off += 2 + elen;
      }
      if (nex_assoc_have_bssid && nex_assoc_freq())
        nex_assoc_start();          /* start early; the gate waits at EAPOL */
      return;
    }
  } else if (type == 2 && nex_frame_class(f, flen) == NEX_F_EAPOL) {
    nex_assoc_gate();
  }
}
#endif /* ARCH_ARMHF — committed-association lane */

#if defined(ARCH_ARMHF)
// ── TicWatch Pro 3: radiotap preamble on the wl_send_hook lane ────────────
// The watch firmware injects a frame only when its first two bytes are zero —
// radiotap it_version and it_pad — and then strips *((char *) p->data + 2)
// bytes off the front before transmitting the rest (injection.c in the
// bcm43430a1 and bcm43436b0 patches). A bare 802.11 frame written to the raw
// socket is therefore never injected: it goes out as an ordinary data frame.
// Such frames get a minimal 8-byte header in front of them here, and a frame
// that already carries radiotap is passed through untouched. It carries no
// rate field, so the firmware sends it at its default rate; tools that set a
// rate in their own radiotap header keep it.
static const unsigned char _dummy_radiotap[8] = {0, 0, 8, 0, 0, 0, 0, 0};
static __thread unsigned char _tx_buf_storage[MAX_INJECT_BUF];

// nex_last_note is declared up in the diagnostics block; each branch below
// leaves a description of what it did there for the per-frame log line.

static int nex_looks_like_radiotap(const void *buf, size_t len) {
  const unsigned char *b = (const unsigned char *)buf;
  return len >= sizeof(_dummy_radiotap) && b[0] == 0 && b[1] == 0 &&
         b[2] >= sizeof(_dummy_radiotap);
}

// The buffer to write and its length: either one of the caller's (it already
// carries radiotap, or the preamble is disabled) or the thread-local copy with
// the flattened iovecs behind the dummy header. NULL means the frame is too
// large to copy — callers then send it as it is. *copied tells the
// vector-aware callers which of the two they got.
static const void *nex_raw_tx_iov(const struct iovec *iov, size_t iovlen,
                                  size_t *out_len, int *copied) {
  size_t total = 0, off = 0, i;
  int has_rtap;

  *copied = 0;
  for (i = 0; i < iovlen; i++)
    total += iov[i].iov_len;
  *out_len = total;
  if (total == 0) {
    nex_last_note = "empty frame, nothing sent";
    nex_last_frame[0] = 0;
    nex_last_class = NEX_F_UNKNOWN;
    return NULL;
  }

  // A frame that brings its own header keeps it, even when the tool split the
  // header and the body across iovecs.
  has_rtap = nex_looks_like_radiotap(iov[0].iov_base, iov[0].iov_len);

  if (iovlen == 1 && (nex_radiotap_disabled || has_rtap)) {
    if (has_rtap) {
      nex_rtap_kept++;
      nex_last_note = "already carries radiotap, passed through untouched";
    } else {
      nex_rtap_off++;
      nex_last_note = "preamble disabled by NEXMON_RAW_NO_RADIOTAP, sent bare";
    }
    nex_note_frame(iov[0].iov_base, total);
    return iov[0].iov_base;
  }

  if ((total + sizeof(_dummy_radiotap)) > MAX_INJECT_BUF) {
    nex_rtap_oversize++;
    nex_last_note = "too large to put a preamble in front of, sent bare "
                    "(wl_send_hook will drop it)";
    nex_last_frame[0] = 0;
    nex_last_class = NEX_F_UNKNOWN;
    return NULL;
  }

  if (nex_radiotap_disabled || has_rtap) {
    for (i = 0; i < iovlen; i++) {
      memcpy(_tx_buf_storage + off, iov[i].iov_base, iov[i].iov_len);
      off += iov[i].iov_len;
    }
    *copied = 1;
    if (has_rtap) {
      nex_rtap_kept++;
      nex_last_note = "split iovecs flattened behind its own radiotap header";
    } else {
      nex_rtap_off++;
      nex_last_note = "split iovecs flattened, sent bare (preamble disabled)";
    }
    nex_note_frame(_tx_buf_storage, total);
    return _tx_buf_storage;
  }

  for (i = 0; i < iovlen; i++) {
    memcpy(_tx_buf_storage + sizeof(_dummy_radiotap) + off, iov[i].iov_base,
           iov[i].iov_len);
    off += iov[i].iov_len;
  }
  memcpy(_tx_buf_storage, _dummy_radiotap, sizeof(_dummy_radiotap));

  nex_rtap_added++;
  nex_last_note = iovlen > 1
                      ? "8-byte radiotap preamble added, split iovecs flattened"
                      : "8-byte radiotap preamble added";

  *out_len = total + sizeof(_dummy_radiotap);
  *copied = 1;
  nex_note_frame(_tx_buf_storage, *out_len);
  return _tx_buf_storage;
}

static const void *nex_raw_tx(const void *buf, size_t len, size_t *out_len) {
  struct iovec iov = {.iov_base = (void *)buf, .iov_len = len};
  int copied = 0;
  const void *tx = nex_raw_tx_iov(&iov, 1, out_len, &copied);

  if (!tx) {
    *out_len = len;
    return buf;
  }
  return tx;
}

// The five transmit hooks call these instead of func_* on the raw lane. They
// report the caller's byte count on success — the tool wrote its frame, the
// extra radiotap header is this library's business.
static ssize_t nex_raw_write(int fd, const void *buf, size_t count) {
  size_t tx_len = 0;
  const void *tx = nex_raw_tx(buf, count, &tx_len);
  ssize_t written = func_write(fd, tx, tx_len);
  nex_last_errno = (written < 0) ? errno : 0;

  return (written > 0) ? (ssize_t)count : written;
}

static ssize_t nex_raw_sendto(int fd, const void *buf, size_t len, int flags,
                              const struct sockaddr *dst, socklen_t dstlen) {
  size_t tx_len = 0;
  const void *tx = nex_raw_tx(buf, len, &tx_len);
  ssize_t written = func_sendto(fd, tx, tx_len, flags, dst, dstlen);
  nex_last_errno = (written < 0) ? errno : 0;

  return (written > 0) ? (ssize_t)len : written;
}

static ssize_t nex_raw_send(int fd, const void *buf, size_t len, int flags) {
  size_t tx_len = 0;
  const void *tx = nex_raw_tx(buf, len, &tx_len);
  ssize_t written = func_send(fd, tx, tx_len, flags);
  nex_last_errno = (written < 0) ? errno : 0;

  return (written > 0) ? (ssize_t)len : written;
}

static ssize_t nex_raw_sendmsg(int fd, const struct msghdr *msg, int flags) {
  size_t total = 0, tx_len = 0;
  int copied = 0;
  const void *tx;
  ssize_t written;

  for (size_t i = 0; i < msg->msg_iovlen; i++)
    total += msg->msg_iov[i].iov_len;

  tx = nex_raw_tx_iov(msg->msg_iov, msg->msg_iovlen, &tx_len, &copied);
  // Only a rewritten frame has to be flattened into a sendto; an untouched one
  // keeps its original msghdr, control data and all.
  if (!copied) {
    written = func_sendmsg(fd, msg, flags);
    nex_last_errno = (written < 0) ? errno : 0;
    return written;
  }

  written = func_sendto(fd, tx, tx_len, flags, msg->msg_name, msg->msg_namelen);
  nex_last_errno = (written < 0) ? errno : 0;
  return (written > 0) ? (ssize_t)total : written;
}

static int nex_raw_sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen,
                            int flags) {
  // Each message needs the preamble on its own terms, so they go out one at a
  // time — sendmmsg cannot carry a different buffer per message otherwise.
  int sent = 0;

  for (unsigned int i = 0; i < vlen; i++) {
    struct msghdr *msg = &msgvec[i].msg_hdr;
    size_t total = 0, tx_len = 0;
    int copied = 0;
    const void *tx;
    ssize_t written;

    for (size_t j = 0; j < msg->msg_iovlen; j++)
      total += msg->msg_iov[j].iov_len;

    tx = nex_raw_tx_iov(msg->msg_iov, msg->msg_iovlen, &tx_len, &copied);
    if (copied)
      written = func_sendto(fd, tx, tx_len, flags, msg->msg_name,
                            msg->msg_namelen);
    else
      written = func_sendmsg(fd, msg, flags);
    nex_last_errno = (written < 0) ? errno : 0;
    if (written < 0)
      break;

    msgvec[i].msg_len = (unsigned int)total;
    sent++;
  }

  return sent;
}
#endif // ARCH_ARMHF

ssize_t write(int fd, const void *buf, size_t count) {
  ssize_t ret;

  int inject = 0;

  // Method 1: Bound socket (standard path)
  if ((fd > 2) && (fd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[fd] == SOCK_RAW) && (bound_to_correct_if[fd] == 1)) {
    inject = 1;
  }

  // Method 2: Unbound raw socket (fallback for aireplay-ng deauth)
  // Some versions of aireplay-ng don't bind() before write()
  // On monitor mode devices, raw socket writes are almost always injection
  if (!inject && (fd > 2) &&
      (fd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[fd] == SOCK_RAW)) {
    inject = 1;
  }

  // Safety: If buf is NULL or length is 0, skip injection (handles mmap flushes)
  if (inject && (!buf || count == 0)) {
      inject = 0;
  }

#if defined(ARCH_ARMHF)
  const char *blk = NULL;
  nex_seen_write++;
  if (inject) {
    nex_inj_write++;
  } else if (fd <= 2) {
    blk = "fd is a standard stream";
  } else if (fd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    blk = "fd is beyond the tracked range";
  } else if (socket_to_type[fd] != SOCK_RAW) {
    blk = "fd is not a tracked raw socket (socket() never saw it, or it is "
          "SOCK_DGRAM/SOCK_PACKET)";
  } else {
    blk = "null buffer or zero-length write";
  }
#endif

  if (inject) {
    if (current_inject_method == INJECT_RAW_SOCKET) {
      // Raw socket passthrough (brcmfmac-style): Injection via wl_send_hook in firmware
      // The firmware intercepts raw socket writes when in monitor mode
      // and checks for radiotap header (((short *)p->data)[0] == 0)
      // So we pass through to the real write() syscall
#if defined(ARCH_ARMHF)
      // On the watch that radiotap header has to actually be there for the
      // frame to be injected, so it is added when the tool sent a bare one.
      ret = nex_raw_write(fd, buf, count);
#else
      ret = func_write(fd, buf, count);
#endif
    } else {
      // IOCTL injection (bcmdhd-style): Injection via NEX_INJECT_FRAME IOCTL
      if ((count + sizeof(struct inject_frame)) > MAX_INJECT_BUF) {
         // Fallback for oversized packets (rare)
         struct inject_frame *buf_dup = (struct inject_frame *)malloc(count + sizeof(struct inject_frame));
         buf_dup->len = count + sizeof(struct inject_frame);
         buf_dup->pad = 0;
         buf_dup->type = 1;
         memcpy(buf_dup->data, buf, count);
         nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, count + sizeof(struct inject_frame), true);
         free(buf_dup);
      } else {
         // Fast Path: Static Buffer
         struct inject_frame *buf_dup = (struct inject_frame *) _inject_buf_storage;
         buf_dup->len = count + sizeof(struct inject_frame);
         buf_dup->pad = 0;
         buf_dup->type = 1;
         memcpy(buf_dup->data, buf, count);
         nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, count + sizeof(struct inject_frame), true);
      }
      ret = count;
    }

    // Configurable rate-limiting
    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }
#if defined(ARCH_ARMHF)
    nex_tx_result("write", fd, count, ret, NULL);
#endif
  } else {
    // otherwise write the regular frame to the socket
    ret = func_write(fd, buf, count);
#if defined(ARCH_ARMHF)
    nex_tx_passthru("write", fd, count, blk);
#endif
  }

  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  ssize_t ret;

  // check if the user wants to write on a raw socket
  int inject = 0;

#if defined(ARCH_ARMHF)
  const char *blk = NULL;
  const char *how = NULL;
#endif

  // Method 1: Check if socket was bound to correct interface
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
#if defined(ARCH_ARMHF)
    how = "raw socket bound to the interface";
#endif
  }

  // Method 2: Check destination address provided in sendto (used by Reaver)
  if (!inject && dest_addr && (sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW)) {
    struct sockaddr_ll *sll = (struct sockaddr_ll *)dest_addr;
    if (sll->sll_ifindex == if_nametoindex(ifname)) {
      inject = 1;
#if defined(ARCH_ARMHF)
      how = "raw socket, destination address names the interface";
#endif
    }
  }

#if defined(ARCH_ARMHF)
  nex_seen_sendto++;
  if (inject) {
    nex_inj_sendto++;
  } else if (sockfd <= 2) {
    blk = "fd is a standard stream";
  } else if (sockfd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    blk = "fd is beyond the tracked range";
  } else if (socket_to_type[sockfd] != SOCK_RAW) {
    blk = "fd is not a tracked raw socket";
  } else if (bound_to_correct_if[sockfd] != 1 && dest_addr) {
    blk = "raw socket, but it is not bound to the interface and its "
          "destination address names a different one";
  } else {
    blk = "raw socket, but not bound to the interface and no destination "
          "address was given";
  }
#endif

  if (inject) {
    if (current_inject_method == INJECT_RAW_SOCKET) {
      // Raw socket passthrough (brcmfmac-style): pass through to real sendto — firmware wl_send_hook handles injection
#if defined(ARCH_ARMHF)
      ret = nex_raw_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#else
      ret = func_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#endif
    } else {
      // IOCTL injection (bcmdhd-style): NEX_INJECT_FRAME IOCTL path
      size_t frame_len = len + sizeof(struct inject_frame);

      if (frame_len > MAX_INJECT_BUF) {
          struct inject_frame *buf_dup = (struct inject_frame *)malloc(frame_len);
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          memcpy(buf_dup->data, buf, len);
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
          free(buf_dup);
      } else {
          struct inject_frame *buf_dup = (struct inject_frame *) _inject_buf_storage;
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          memcpy(buf_dup->data, buf, len);
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
      }
      ret = len;
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    // Periodic stability enforcement during injection
    // Prevents radio from going to sleep during long capture sessions
    // Every 50 frames, re-enforce wake state (not for aireplay - it's too fast)
    static int inject_counter_sendto = 0;
    if (!is_aireplay && ++inject_counter_sendto >= 50) {
        inject_counter_sendto = 0;
        nex_enforce_stability();
    }
#if defined(ARCH_ARMHF)
    nex_tx_result("sendto", sockfd, len, ret, how);
#endif
  } else {
    // otherwise write the regular frame to the socket
    ret = func_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
#if defined(ARCH_ARMHF)
    nex_tx_passthru("sendto", sockfd, len, blk);
#endif
  }

  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ssize_t ret;
  int inject = 0;

#if defined(ARCH_ARMHF)
  const char *blk = NULL;
  const char *how = NULL;
  size_t nex_payload = 0;
#endif

  // Check for injection path - Method 1 (Socket Bound)
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
#if defined(ARCH_ARMHF)
    how = "raw socket bound to the interface";
#endif
  }

  // Check for injection path - Method 2 (Destination Interface)
  if (!inject && msg->msg_name && (sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW)) {
    struct sockaddr_ll *sll = (struct sockaddr_ll *)msg->msg_name;
    if (sll->sll_ifindex == if_nametoindex(ifname)) {
      inject = 1;
#if defined(ARCH_ARMHF)
      how = "raw socket, msg_name names the interface";
#endif
    }
  }

  // Safety: Ensure iov is valid
  if (inject && (!msg->msg_iov || msg->msg_iovlen == 0)) {
      inject = 0;
  }

#if defined(ARCH_ARMHF)
  if (inject && msg->msg_iov)
    for (size_t i = 0; i < msg->msg_iovlen; i++)
      nex_payload += msg->msg_iov[i].iov_len;

  nex_seen_sendmsg++;
  if (inject) {
    nex_inj_sendmsg++;
  } else if (sockfd <= 2) {
    blk = "fd is a standard stream";
  } else if (sockfd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    blk = "fd is beyond the tracked range";
  } else if (socket_to_type[sockfd] != SOCK_RAW) {
    blk = "fd is not a tracked raw socket";
  } else {
    blk = "raw socket, but not bound to the interface, msg_name does not name "
          "it, or the iovec is empty";
  }
#endif

  if (inject) {
    if (current_inject_method == INJECT_RAW_SOCKET) {
      // Raw socket passthrough (brcmfmac-style): pass through to real sendmsg — firmware wl_send_hook handles injection
#if defined(ARCH_ARMHF)
      ret = nex_raw_sendmsg(sockfd, msg, flags);
#else
      ret = func_sendmsg(sockfd, msg, flags);
#endif
    } else {
      // IOCTL injection (bcmdhd-style): Flatten iovec for NEX_INJECT_FRAME IOCTL
      size_t total_len = 0;
      for (size_t i = 0; i < msg->msg_iovlen; i++) {
        total_len += msg->msg_iov[i].iov_len;
      }

      size_t frame_len = total_len + sizeof(struct inject_frame);

      if (frame_len > MAX_INJECT_BUF) {
          struct inject_frame *buf_dup = (struct inject_frame *)malloc(frame_len);
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          size_t offset = 0;
          for (size_t i = 0; i < msg->msg_iovlen; i++) {
             memcpy(buf_dup->data + offset, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
             offset += msg->msg_iov[i].iov_len;
          }
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
          free(buf_dup);
      } else {
          struct inject_frame *buf_dup = (struct inject_frame *) _inject_buf_storage;
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          size_t offset = 0;
          for (size_t i = 0; i < msg->msg_iovlen; i++) {
             memcpy(buf_dup->data + offset, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
             offset += msg->msg_iov[i].iov_len;
          }
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
      }
      ret = total_len;
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    // Periodic stability enforcement (same as sendto)
    static int inject_counter_sendmsg = 0;
    if (!is_aireplay && ++inject_counter_sendmsg >= 50) {
        inject_counter_sendmsg = 0;
        nex_enforce_stability();
    }
#if defined(ARCH_ARMHF)
    nex_tx_result("sendmsg", sockfd, nex_payload, ret, how);
#endif
  } else {
    ret = func_sendmsg(sockfd, msg, flags);
#if defined(ARCH_ARMHF)
    nex_tx_passthru("sendmsg", sockfd, nex_payload, blk);
#endif
  }

  return ret;
}

#if defined(ARCH_ARMHF) && defined(__TIMESIZE) && __TIMESIZE == 32
/* The mirror image of the __ioctl_time64 note above, and here the direction is
 * the opposite one: this file's own <sys/socket.h> renamed the definition to
 * __sendmsg64 (sendmsg is a large-file interface, so it takes the LFS rename),
 * while a tool is free to call either spelling. */
ssize_t nex_sendmsg_plain(int, const struct msghdr *, int) __asm__("sendmsg");
ssize_t nex_sendmsg_plain(int sockfd, const struct msghdr *msg, int flags)
    __attribute__((alias("__sendmsg64")));
#endif

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  ssize_t ret;
  int inject = 0;

#if defined(ARCH_ARMHF)
  const char *blk = NULL;
#endif

  // Check for injection path
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
  }

#if defined(ARCH_ARMHF)
  nex_seen_send++;
  if (inject) {
    nex_inj_send++;
  } else if (sockfd <= 2) {
    blk = "fd is a standard stream";
  } else if (sockfd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    blk = "fd is beyond the tracked range";
  } else if (socket_to_type[sockfd] != SOCK_RAW) {
    blk = "fd is not a tracked raw socket";
  } else {
    blk = "raw socket, but never bound to the interface — send() gives no "
          "destination address to fall back on, so bind() first";
  }
#endif

  if (inject) {
    if (current_inject_method == INJECT_RAW_SOCKET) {
      // Raw socket passthrough (brcmfmac-style): pass through to real send — firmware wl_send_hook handles injection
#if defined(ARCH_ARMHF)
      ret = nex_raw_send(sockfd, buf, len, flags);
#else
      ret = func_send(sockfd, buf, len, flags);
#endif
    } else {
      // IOCTL injection (bcmdhd-style): NEX_INJECT_FRAME IOCTL path
      size_t frame_len = len + sizeof(struct inject_frame);
      
      if (frame_len > MAX_INJECT_BUF) {
          struct inject_frame *buf_dup = (struct inject_frame *)malloc(frame_len);
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          memcpy(buf_dup->data, buf, len);
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
          free(buf_dup);
      } else {
          struct inject_frame *buf_dup = (struct inject_frame *) _inject_buf_storage;
          buf_dup->len = frame_len;
          buf_dup->pad = 0;
          buf_dup->type = 1;
          memcpy(buf_dup->data, buf, len);
          nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
      }
      ret = len;
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    // Periodic stability enforcement (same as sendto)
    static int inject_counter_send = 0;
    if (!is_aireplay && ++inject_counter_send >= 50) {
        inject_counter_send = 0;
        nex_enforce_stability();
    }
#if defined(ARCH_ARMHF)
    nex_tx_result("send", sockfd, len, ret, NULL);
#endif
  } else {
    ret = func_send(sockfd, buf, len, flags);
#if defined(ARCH_ARMHF)
    nex_tx_passthru("send", sockfd, len, blk);
#endif
  }
  return ret;
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  int ret;
  int inject = 0;

#if defined(ARCH_ARMHF)
  const char *blk = NULL;
#endif

  // Check for injection path
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
  }

  // Safety: Ensure valid vector
  if (inject && (!msgvec || vlen == 0)) {
      inject = 0;
  }

#if defined(ARCH_ARMHF)
  nex_seen_sendmmsg++;
  if (inject) {
    nex_inj_sendmmsg++;
  } else if (sockfd <= 2) {
    blk = "fd is a standard stream";
  } else if (sockfd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0]))) {
    blk = "fd is beyond the tracked range";
  } else if (socket_to_type[sockfd] != SOCK_RAW) {
    blk = "fd is not a tracked raw socket";
  } else if (!msgvec || vlen == 0) {
    blk = "null message vector or zero messages";
  } else {
    blk = "raw socket, but never bound to the interface — sendmmsg carries no "
          "destination address, so bind() first";
  }
#endif

  if (inject) {
    if (current_inject_method == INJECT_RAW_SOCKET) {
      // Raw socket passthrough (brcmfmac-style): pass through to real sendmmsg — firmware wl_send_hook handles injection
#if defined(ARCH_ARMHF)
      ret = nex_raw_sendmmsg(sockfd, msgvec, vlen, flags);
#else
      ret = func_sendmmsg(sockfd, msgvec, vlen, flags);
#endif
    } else {
      // IOCTL injection (bcmdhd-style): NEX_INJECT_FRAME IOCTL path
      for (unsigned int i = 0; i < vlen; i++) {
          struct msghdr *msg = &msgvec[i].msg_hdr;

          size_t total_len = 0;
          for (size_t j = 0; j < msg->msg_iovlen; j++) {
              total_len += msg->msg_iov[j].iov_len;
          }

          size_t frame_len = total_len + sizeof(struct inject_frame);

          if (frame_len > MAX_INJECT_BUF) {
              struct inject_frame *buf_dup = (struct inject_frame *)malloc(frame_len);
              buf_dup->len = frame_len;
              buf_dup->pad = 0;
              buf_dup->type = 1;
              size_t offset = 0;
              for (size_t j = 0; j < msg->msg_iovlen; j++) {
                  memcpy(buf_dup->data + offset, msg->msg_iov[j].iov_base, msg->msg_iov[j].iov_len);
                  offset += msg->msg_iov[j].iov_len;
              }
              nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
              free(buf_dup);
          } else {
              struct inject_frame *buf_dup = (struct inject_frame *) _inject_buf_storage;
              buf_dup->len = frame_len;
              buf_dup->pad = 0;
              buf_dup->type = 1;
              size_t offset = 0;
              for (size_t j = 0; j < msg->msg_iovlen; j++) {
                  memcpy(buf_dup->data + offset, msg->msg_iov[j].iov_base, msg->msg_iov[j].iov_len);
                  offset += msg->msg_iov[j].iov_len;
              }
              nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
          }

          msgvec[i].msg_len = total_len;
      }
      ret = vlen;
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    // Periodic stability enforcement (same as sendto)
    static int inject_counter_sendmmsg = 0;
    if (!is_aireplay && ++inject_counter_sendmmsg >= 50) {
        inject_counter_sendmmsg = 0;
        nex_enforce_stability();
    }
#if defined(ARCH_ARMHF)
    nex_tx_result("sendmmsg", sockfd, vlen, ret, NULL);
#endif
  } else {
    ret = func_sendmmsg(sockfd, msgvec, vlen, flags);
#if defined(ARCH_ARMHF)
    nex_tx_passthru("sendmmsg", sockfd, vlen, blk);
#endif
  }
  return ret;
}

#if defined(ARCH_ARMHF) && defined(__TIMESIZE) && __TIMESIZE == 32
/* And the same for sendmmsg — see the __ioctl_time64 note above. */
int nex_sendmmsg_time64(int, struct mmsghdr *, unsigned int, int)
    __asm__("__sendmmsg64");
int nex_sendmmsg_time64(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                        int flags) __attribute__((alias("sendmmsg")));
#endif

#if defined(ARCH_ARMHF)
/* ── The receive side ────────────────────────────────────────────────────
 *
 * Injection is only half of an authentication exchange: the AP's answer has to
 * come back up to the tool. Nothing about that is visible from outside — a
 * frame the radio never delivered and a frame the tool discarded look the same
 * in the tool's output, and no tool says which frames it actually saw. So
 * every frame that arrives on a raw socket bound to our interface is named
 * here, and the ones that carry an exchange (EAPOL, the association answers, a
 * deauth) are announced even at level 1.
 *
 * Three receive calls can deliver them and which one a tool uses is decided by
 * how it was built, not by what it means to do: libpcap's Linux backend reads
 * with recvfrom(), libnl reads with recvmsg(), and the rest use read(). All
 * three are covered and all three are counted separately, so a silent receive
 * log is never ambiguous between "nothing arrived" and "it arrived through a
 * call this library does not hook".
 *
 * Cost: classifying a frame is a few byte reads and formats nothing, so it is
 * safe on every frame of a busy capture. The snprintf happens only for frames
 * that will be printed.
 */
static void nex_rx_report(const void *buf, size_t len, int hook) {
  const unsigned char *b = (const unsigned char *)buf;
  const unsigned char *f;
  size_t flen, rtap;
  unsigned cls, type, st;
  const char *viacall = hook == NEX_HOOK_RECVFROM ? "recvfrom"
                        : hook == NEX_HOOK_RECVMSG ? "recvmsg" : "read";
  char name[64], peer[24];

  if (!b || len < 2)
    return;

  if (hook == NEX_HOOK_RECVFROM)
    nex_rx_hook_recvfrom++;
  else if (hook == NEX_HOOK_RECVMSG)
    nex_rx_hook_recvmsg++;
  else
    nex_rx_hook_read++;

  f = nex_80211(b, len, &flen, &rtap);
  cls = nex_frame_class(f, flen);
  type = (f[0] >> 2) & 0x3;
  st = (f[0] >> 4) & 0xf;

  nex_rx_total++;
  switch (cls) {
    case NEX_F_MGMT: nex_rx_mgmt_n++; break;
    case NEX_F_DATA: nex_rx_data_n++; break;
    case NEX_F_EAPOL: nex_rx_eapol_n++; break;
    default: nex_rx_unk_n++; break;
  }
  if (type == 0 && (st == 10 || st == 12))
    nex_rx_deauth_n++;

  /* The frames that carry the conversation, printed whether or not per-frame
   * logging is on. A run where the AP answers and a run where it never speaks
   * must not look the same at the level the operator actually uses. */
  if (cls == NEX_F_EAPOL || (type == 0 && (st == 1 || st == 10 || st == 11 || st == 12))) {
    if (nex_rx_announced < 32) {
      nex_rx_announced++;
      nex_frame_name(f, flen, name, sizeof(name));
      nex_frame_peer(f, flen, 1, peer, sizeof(peer));
      nex_logf("rx %s%s%s (%zu B via %s) — %s", name, peer[0] ? " from " : "",
               peer, len, viacall,
               cls == NEX_F_EAPOL ? "the exchange is alive"
               : st == 12 || st == 10 ? "the AP is dropping us"
                                      : "the AP is answering");
    }
  } else if (nex_rx_first < 3) {
    nex_rx_first++;
    nex_frame_name(f, flen, name, sizeof(name));
    nex_frame_peer(f, flen, 1, peer, sizeof(peer));
    nex_logf("rx first frames: %s%s%s (%zu B via %s) — receive is working",
             name, peer[0] ? " from " : "", peer, len, viacall);
  }

  if (nex_dbg >= 2) {
    nex_rx_frames++;
    if (nex_rx_frames <= NEX_LOG_FIRST || (nex_rx_frames % NEX_LOG_EVERY) == 0) {
      nex_frame_name(f, flen, name, sizeof(name));
      nex_frame_peer(f, flen, 1, peer, sizeof(peer));
      nex_rxf("%s%s%s (%zu B via %s)%s", name, peer[0] ? " from " : "", peer, len,
              viacall, rtap ? "" : " — no radiotap (mode 1?)");
    }
  }
}

/* Only on a raw socket this library saw created and bound to the interface it
 * watches. Netlink sockets are SOCK_RAW too and would otherwise be read as
 * frames — they are counted by the netlink hooks instead. */
static void nex_rx_maybe(int fd, const void *buf, size_t len, int hook) {
  if (fd <= 0 ||
      fd >= (int)(sizeof(socket_to_type) / sizeof(socket_to_type[0])))
    return;
  if (socket_is_netlink[fd] || socket_to_type[fd] != SOCK_RAW)
    return;
  if (!bound_to_correct_if[fd])
    return;
  /* Said once, at the level an operator actually runs. "The tool reports
   * silence" and "the tool never received anything at all" are different
   * failures and the log must not leave them looking alike. */
  if (nex_rx_total == 0)
    nex_logf("first frame received (fd=%d via %s) — a run that never shows this "
             "line received nothing at all, whatever the tool printed",
             fd, hook == NEX_HOOK_RECVFROM ? "recvfrom"
                 : hook == NEX_HOOK_RECVMSG ? "recvmsg" : "read");
  nex_rx_report(buf, len, hook);
}

/* recvmsg() carries its bytes in iovecs; everything that matters here fits in
 * the first one, which is where a packet socket puts the frame. */
static const void *nex_rx_first_iov(const struct msghdr *msg, ssize_t n) {
  if (!msg || !msg->msg_iov || msg->msg_iovlen == 0 || !msg->msg_iov[0].iov_base)
    return NULL;
  return msg->msg_iov[0].iov_base;
}

/* ── setsockopt(): the BPF filter a capture tool installs on its own socket ─
 *
 * reaver compiles `wlan type mgt or wlan type data` and libpcap turns that into
 * BPF, attached with SO_ATTACH_FILTER. The kernel then discards every frame
 * that does not match, before the process can see it — so a filter that does
 * not match what this firmware actually delivers is indistinguishable from a
 * radio that delivers nothing, and that is one of the open questions about the
 * WPS run. A BPF program is an array of `struct sock_filter`; if no instruction
 * returns non-zero, it drops everything.
 *
 * The request is passed through untouched either way; this only records it.
 */
static int (*func_setsockopt)(int, int, int, const void *, socklen_t) = NULL;

int nex_setsockopt_body(int fd, int level, int optname, const void *optval,
                        socklen_t optlen) {
  if (!func_setsockopt)
    func_setsockopt = (int (*)(int, int, int, const void *,
                               socklen_t))dlsym(REAL_LIBC, "setsockopt");

  if (level == SOL_SOCKET && optname == SO_ATTACH_FILTER && optval &&
      optlen >= sizeof(struct sock_fprog)) {
    const struct sock_fprog *prog = (const struct sock_fprog *)optval;
    unsigned i, pass = 0, rets = 0;
    if (prog->filter && prog->len > 0) {
      for (i = 0; i < prog->len; i++) {
        if (BPF_CLASS(prog->filter[i].code) == BPF_RET) {
          rets++;
          if (prog->filter[i].k != 0)
            pass = 1;
        }
      }
    }
    if (nex_filter_n < NEX_FILTERS) {
      nex_filter_seen[nex_filter_n].fd = fd;
      nex_filter_seen[nex_filter_n].pass = (int)pass;
      nex_filter_n++;
    }
    nex_logf("setsockopt(fd=%d, SO_ATTACH_FILTER): %u instruction(s), %u return(s), "
             "%-24s — %s", fd, prog->len, rets,
             pass ? "passes some frames" : "passes nothing at all",
             pass ? "the kernel still delivers what matches"
                  : "every frame this socket receives is discarded in the kernel "
                    "before any receive call can see it");
  }

  return func_setsockopt(fd, level, optname, optval, optlen);
}
int setsockopt(int, int, int, const void *, socklen_t)
    __attribute__((alias("nex_setsockopt_body")));

#if defined(__TIMESIZE) && __TIMESIZE == 32
/* Which spelling of the name actually gets hooked is decided by glibc, not by
 * this file. <sys/socket.h> declares setsockopt through __REDIRECT_NTH with an
 * asm name on this ABI, so the definition above is emitted as __setsockopt64 —
 * that is the name a tool built with _TIME_BITS=64 (reaver, wash, hcxdumptool
 * on Kali/Debian armhf) calls, and the one that must be caught for the
 * SO_ATTACH_FILTER diagnostic to say whether `wlan type mgt or wlan type data`
 * passes anything at all. A tool built without the 64-bit time ABI calls the
 * plain spelling and would go straight to libc, so that one is aliased here by
 * hand — the same mirror as the __sendmsg64 note further down. */
int nex_setsockopt_plain(int, int, int, const void *, socklen_t)
    __asm__("setsockopt");
int nex_setsockopt_plain(int fd, int level, int optname, const void *optval,
                         socklen_t optlen)
    __attribute__((alias("nex_setsockopt_body")));
#endif
#endif // ARCH_ARMHF

// read() hook for error suppression
// Kismet and hcxdumptool read from netlink sockets to get interface stats
// When the kernel returns EOPNOTSUPP (-95) or EINVAL (-22), we rewrite to success
// This prevents tools from aborting due to "Driver does not support X" errors
// CRITICAL: Only apply to netlink sockets to avoid corrupting packet capture data
ssize_t read(int fd, void *buf, size_t count) {
    if (!func_read)
        func_read = (ssize_t (*)(int, void *, size_t))dlsym(REAL_LIBC, "read");
    
    ssize_t ret = func_read(fd, buf, count);
    
    // Error suppression ONLY for Kismet/hcxdumptool reading from NETLINK sockets
    // Do NOT apply to AF_PACKET sockets used for packet capture - this would corrupt data
    if ((is_kismet || is_hcxdumptool) && ret > 0 && buf && 
        fd > 0 && fd < (int)(sizeof(socket_is_netlink) / sizeof(socket_is_netlink[0])) &&
        socket_is_netlink[fd] &&  // ONLY netlink sockets!
        ret >= (ssize_t)sizeof(struct nlmsghdr)) {
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        
        // Check for netlink error messages (NLMSG_ERROR type)
        if (nlh->nlmsg_type == NLMSG_ERROR && 
            ret >= (ssize_t)(sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr))) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
            
            // Suppress EOPNOTSUPP (-95) and EINVAL (-22)
            // These occur when the kernel doesn't support the requested operation
            if (err->error == -95 || err->error == -22) {
#if defined(ARCH_ARMHF)
                nex_nl_suppressed++;
                nex_dbgf("read(): rewrote netlink error %d (%s) to success",
                         err->error, err->error == -95 ? "EOPNOTSUPP" : "EINVAL");
#endif
                err->error = 0; // Rewrite to success
            }
        }
    }

#if defined(ARCH_ARMHF)
    // A netlink read means the tool is talking to nl80211 — which is how
    // Kismet and hcxdumptool do their setup, and where the fake above sits.
    if (ret > 0 && fd > 0 &&
        fd < (int)(sizeof(socket_is_netlink) / sizeof(socket_is_netlink[0]))) {
        if (socket_is_netlink[fd])
            nex_rx_netlink++;
        else
            nex_rx_other++;
    }
    // And if what came in is a frame on a raw socket bound to the interface
    // under test, it is part of the conversation this library is here to make
    // visible — see nex_rx_report().
    if (ret > 0 && buf)
        nex_rx_maybe(fd, buf, (size_t)ret, NEX_HOOK_READ);
#endif

    return ret;
}

#if defined(ARCH_ARMHF)
/* ── recv() and recvfrom(): where libpcap's capture actually arrives ──────
 *
 * Both spellings are needed and neither implies the other: glibc's recv() does
 * not call the exported recvfrom(), so a tool that calls one of them is
 * invisible to a hook on the other. Neither call is modified here — the real
 * function runs first and its result is returned untouched; the frame is only
 * described. That is deliberate on the capture path, which has to keep working
 * exactly as it does now.
 */
static ssize_t (*func_recvfrom)(int, void *, size_t, int, struct sockaddr *,
                                socklen_t *) = NULL;
static ssize_t (*func_recv)(int, void *, size_t, int) = NULL;

ssize_t nex_recvfrom_body(int, void *, size_t, int, struct sockaddr *,
                          socklen_t *);
ssize_t nex_recvfrom_body(int fd, void *buf, size_t len, int flags,
                          struct sockaddr *src, socklen_t *slen) {
  if (!func_recvfrom)
    func_recvfrom = (ssize_t (*)(int, void *, size_t, int, struct sockaddr *,
                                 socklen_t *))dlsym(REAL_LIBC, "recvfrom");
  ssize_t ret = func_recvfrom(fd, buf, len, flags, src, slen);
  if (ret > 0 && buf)
    nex_rx_maybe(fd, buf, (size_t)ret, NEX_HOOK_RECVFROM);
  return ret;
}
ssize_t recvfrom(int, void *, size_t, int, struct sockaddr *, socklen_t *)
    __attribute__((alias("nex_recvfrom_body")));

ssize_t nex_recv_body(int, void *, size_t, int);
ssize_t nex_recv_body(int fd, void *buf, size_t len, int flags) {
  if (!func_recv)
    func_recv = (ssize_t (*)(int, void *, size_t, int))dlsym(REAL_LIBC, "recv");
  ssize_t ret = func_recv(fd, buf, len, flags);
  if (ret > 0 && buf)
    nex_rx_maybe(fd, buf, (size_t)ret, NEX_HOOK_RECVFROM);
  return ret;
}
ssize_t recv(int, void *, size_t, int) __attribute__((alias("nex_recv_body")));
#endif // ARCH_ARMHF

#if defined(ARCH_ARMHF)
/* ── recvmsg(): where a libnl tool's netlink replies actually arrive ──────
 *
 * The hook above rewrites a rejected command into a success, but libnl never
 * calls read(): its nl_recv() fills one iovec and calls recvmsg(), twice for
 * the same message — first with MSG_PEEK|MSG_TRUNC to learn the length, then
 * for real. Both spellings are handled below, and a scrub that lands in the
 * peeked copy is harmless because the real call is scrubbed too.
 *
 * This is why Kismet reported errors the library believed it was suppressing:
 * the suppression sat in a hook libnl's receive path never enters.
 *
 * Only a reply to NL80211_CMD_SET_WIPHY is rewritten, and only one this library
 * itself answered on the firmware side — the sequence number identifies it,
 * because an NLMSG_ERROR quotes the rejected header's type and sequence but not
 * the genl command. Everything else keeps its error: Kismet's monitor-vif
 * creation has to fail for it to fall back to the interface it was handed, and
 * a failure it cannot see would send it looking for a vif that does not exist.
 *
 * The read() hook above keeps its older, blunter rule — it is part of the
 * shared code both architectures build, and it is not on this path.
 */
static size_t nex_iov_have(const struct msghdr *msg, ssize_t n) {
  size_t i, total = 0;
  for (i = 0; i < msg->msg_iovlen; i++)
    total += msg->msg_iov[i].iov_len;
  return (size_t)n < total ? (size_t)n : total;
}

/* Copy len bytes of the received stream out of the iovecs, starting at off. */
static void nex_iov_read(const struct msghdr *msg, size_t off, void *dst,
                         size_t len) {
  const struct iovec *v = msg->msg_iov;
  size_t i, base = 0;

  memset(dst, 0, len);
  for (i = 0; i < msg->msg_iovlen && len; i++) {
    size_t end = base + v[i].iov_len;
    if (off < end) {
      size_t skip = off > base ? off - base : 0;
      size_t avail = v[i].iov_len - skip;
      size_t take = len < avail ? len : avail;
      memcpy(dst, (const char *)v[i].iov_base + skip, take);
      dst = (char *)dst + take;
      len -= take;
      off += take;
    }
    base = end;
  }
}

/* The same in reverse. Returns 0 if the bytes did not all fit. */
static int nex_iov_write(const struct msghdr *msg, size_t off, const void *src,
                         size_t len) {
  const struct iovec *v = msg->msg_iov;
  size_t i, base = 0;

  for (i = 0; i < msg->msg_iovlen && len; i++) {
    size_t end = base + v[i].iov_len;
    if (off < end) {
      size_t skip = off > base ? off - base : 0;
      size_t avail = v[i].iov_len - skip;
      size_t take = len < avail ? len : avail;
      memcpy((char *)v[i].iov_base + skip, src, take);
      src = (const char *)src + take;
      len -= take;
      off += take;
    }
    base = end;
  }
  return len == 0;
}

/* Is the firmware in monitor mode right now — asked of the firmware, because
 * the kernel is the party that does not know. The bits are the same ones
 * SIOCGIWMODE and SIOCGIFHWADDR are answered from; WLC_GET_MONITOR is a stock
 * command every patch family carries, so this costs one ioctl and no risk. */
static int nex_fw_in_monitor(void) {
  int buf = 0;
  nex_ioctl(nexio, WLC_GET_MONITOR, &buf, 4, false);
  return (buf & (MONITOR_RADIOTAP | MONITOR_IEEE80211 | MONITOR_LOG_ONLY |
                 MONITOR_DROP_FRM | MONITOR_IPV4_UDP)) != 0;
}

/* Correct the one answer this library cannot pass on unchanged: the interface
 * type.
 *
 * Asked over netlink what kind of interface wlan0 is, the kernel answers from
 * its own registration — MANAGED, because nothing told it otherwise. The
 * firmware, meanwhile, is in monitor mode, put there from Android before the
 * tool started; that is what SIOCGIWMODE reports and what SIOCGIFHWADDR
 * reports. Two answers to one question, and the tool believes the netlink one.
 *
 * What a tool does with the wrong answer is the reason this matters. Kismet
 * reads the type first, and when it is told MANAGED it sets about making a
 * monitor interface: it tries to create a vif (which the kernel refuses), then
 * brings the interface down, sets the mode through the legacy path, and brings
 * it up again. On this watch, taking the radio down and putting it back is a
 * dongle close and re-open, and the firmware is re-downloaded — dhd fetching
 * fw_bcm43438a1.bin is in the pstore log of the boot that died seconds after
 * Kismet started. Told MONITOR, Kismet skips all of it and gets on with
 * capturing, which is the same sequence airodump-ng follows when it works.
 *
 * Only the interface this library drives is touched, only when the firmware
 * really is in monitor mode, and only the type is changed: everything else in
 * the reply is the kernel's own. */
static void nex_nl_fix_iftype(struct msghdr *msg, size_t off,
                              const struct nlmsghdr *nh) {
  struct genlmsghdr gh;
  struct nlattr na;
  size_t a, end;
  uint32_t ifidx = 0, iftype = 0, iftype_at = 0;

  if (nh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
    return;

  nex_iov_read(msg, off + NLMSG_HDRLEN, &gh, sizeof(gh));
  if (gh.cmd != NL80211_CMD_GET_INTERFACE)
    return;

  end = off + nh->nlmsg_len;
  for (a = off + NLMSG_HDRLEN + GENL_HDRLEN; a + sizeof(na) <= end;
       a += NLA_ALIGN(na.nla_len)) {
    nex_iov_read(msg, a, &na, sizeof(na));
    if (na.nla_len < sizeof(na) || a + na.nla_len > end)
      break;
    if (na.nla_type == NL80211_ATTR_IFINDEX && na.nla_len >= sizeof(na) + 4)
      nex_iov_read(msg, a + sizeof(na), &ifidx, 4);
    else if (na.nla_type == NL80211_ATTR_IFTYPE && na.nla_len >= sizeof(na) + 4) {
      nex_iov_read(msg, a + sizeof(na), &iftype, 4);
      iftype_at = a + sizeof(na);
    }
  }

  if (!iftype_at || ifidx != (uint32_t)if_nametoindex(ifname) ||
      iftype != NL80211_IFTYPE_STATION || !nex_fw_in_monitor())
    return;

  iftype = NL80211_IFTYPE_MONITOR;
  if (nex_iov_write(msg, iftype_at, &iftype, 4)) {
    nex_nl_iftype++;
    nex_dbgf("recvmsg(): nl80211 GET_INTERFACE for %s said STATION; answered "
             "MONITOR, which is what the firmware is in — a tool told STATION "
             "takes the radio down and back up to make a monitor interface, and "
             "on this watch that reloads the firmware",
             ifname);
  }
}

static void nex_nl_scrub(struct msghdr *msg, ssize_t n) {
  size_t have = nex_iov_have(msg, n);
  size_t off = 0;
  struct nlmsghdr nh;
  struct nlmsgerr err;

  /* Replies arrive as a stream of messages, each NLMSG_ALIGN(nlmsg_len) apart.
   * Reading past what was received (the peek call reports the whole length while
   * only the buffers' worth was copied) is what the `have` bound is for. */
  while (have - off >= sizeof(nh)) {
    nex_iov_read(msg, off, &nh, sizeof(nh));
    if (nh.nlmsg_len < sizeof(nh) || nh.nlmsg_len > have - off)
      break;

    if (nh.nlmsg_type == NLMSG_ERROR &&
        nh.nlmsg_len >= sizeof(struct nlmsghdr) + sizeof(struct nlmsgerr)) {
      nex_iov_read(msg, off + sizeof(struct nlmsghdr), &err, sizeof(err));
      if ((err.error == -95 || err.error == -22) &&
          nex_nl_reply_is(err.msg.nlmsg_seq, err.msg.nlmsg_type,
                          NL80211_CMD_SET_WIPHY)) {
        int orig = err.error;
        err.error = 0; /* rewrite to success, in the caller's own buffer */
        if (nex_iov_write(msg, off + sizeof(struct nlmsghdr), &err, sizeof(err))) {
          nex_nl_suppressed++;
          nex_dbgf("recvmsg(): rewrote nl80211 SET_WIPHY error %d (%s) to success "
                   "— the channel was set on the firmware side, so the kernel's "
                   "refusal is the wrong answer for this one request",
                   orig, orig == -95 ? "EOPNOTSUPP" : "EINVAL");
        }
      }
    } else if (nh.nlmsg_type == nl80211_type()) {
      nex_nl_fix_iftype(msg, off, &nh);
    }
    off += NLMSG_ALIGN(nh.nlmsg_len);
  }
}

ssize_t nex_recvmsg_body(int fd, struct msghdr *msg, int flags) {
  ssize_t ret;

  if (!func_recvmsg)
    func_recvmsg =
        (ssize_t (*)(int, struct msghdr *, int))dlsym(REAL_LIBC, "recvmsg");

  ret = func_recvmsg(fd, msg, flags);

  if (ret > 0 && fd > 0 &&
      fd < (int)(sizeof(socket_is_netlink) / sizeof(socket_is_netlink[0])) &&
      socket_is_netlink[fd]) {
    nex_rx_msg_netlink++;
    // The scrub is for the tools that hit the SET_INTERFACE fake above. Every
    // other tool's replies pass through the walk untouched.
    if ((is_kismet || is_hcxdumptool) && msg && msg->msg_iov &&
        msg->msg_iovlen > 0)
      nex_nl_scrub(msg, ret);
  } else if (ret > 0) {
    const void *fb = nex_rx_first_iov(msg, ret);
    if (fb)
      nex_rx_maybe(fd, fb, (size_t)ret, NEX_HOOK_RECVMSG);
  }

  return ret;
}

/* Both spellings of the receive, as aliases of one body.
 *
 * Which one a caller reaches depends on how it was built, not on what it means
 * to do: a tool or library compiled with _TIME_BITS=64 — the armhf default on
 * Kali and Debian, and how libnl is built there — has <sys/socket.h> put an
 * assembler label on the plain name, so it calls __recvmsg64, while anything
 * built without it calls recvmsg. The body is deliberately not named recvmsg:
 * this file's own headers carry the same label, which would silently rename a
 * definition to __recvmsg64 and leave the plain name undefined — and an alias
 * can only point at a name that exists. Naming the body here and exporting both
 * spellings works whichever way the toolchain is set up. See the __ioctl_time64
 * and __sendmsg64 notes for the same problem in the other direction. */
ssize_t nex_recvmsg_plain(int, struct msghdr *, int) __asm__("recvmsg");
ssize_t nex_recvmsg_plain(int fd, struct msghdr *msg, int flags)
    __attribute__((alias("nex_recvmsg_body")));

#if defined(__TIMESIZE) && __TIMESIZE == 32
ssize_t nex_recvmsg_time64(int, struct msghdr *, int) __asm__("__recvmsg64");
ssize_t nex_recvmsg_time64(int fd, struct msghdr *msg, int flags)
    __attribute__((alias("nex_recvmsg_body")));
#endif

/* ── nl_wait_for_ack(): the wait for a request that was never sent ────────
 *
 * libnl produces a command's error at the moment the caller waits for the ACK,
 * so Kismet's helper reads a faked SET_INTERFACE as success only if this
 * returns 0 — and with nothing sent there is no ACK to receive, so the real
 * function would block for ever. One wait is answered for each fake recorded,
 * and only for the socket that recorded it.
 */
static int (*func_nl_wait_for_ack)(struct nl_sock *) = NULL;

int nl_wait_for_ack(struct nl_sock *sk) {
  if (nex_nl_fake_take(sk)) {
    nex_nl_waited++;
    nex_dbgf("nl_wait_for_ack(): answered here — the SET_INTERFACE it waits for "
             "was faked and never went to the kernel, so no ACK was ever coming "
             "and waiting would have blocked this tool for ever");
    return 0;
  }

  if (!func_nl_wait_for_ack)
    func_nl_wait_for_ack =
        (int (*)(struct nl_sock *))dlsym(REAL_LIBNL, "nl_wait_for_ack");
  if (!func_nl_wait_for_ack) {
    // Nothing dlopen'd libnl in this process, so this call cannot have come
    // from libnl. Nothing is pending either - say so rather than crash.
    return 0;
  }
  return func_nl_wait_for_ack(sk);
}
#endif /* ARCH_ARMHF */
