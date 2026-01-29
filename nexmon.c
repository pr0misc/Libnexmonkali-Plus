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
  struct ifreq *ifr;
  int sock_rx_ioctl;
  int sock_rx_frame;
  int sock_tx;
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

static int (*func_sendto)(int, const void *, size_t, int,
                          const struct sockaddr *, socklen_t) = NULL;
static ssize_t (*func_sendmsg)(int, const struct msghdr *, int) = NULL;
static ssize_t (*func_send)(int, const void *, size_t, int) = NULL;
static int (*func_sendmmsg)(int, struct mmsghdr *, unsigned int, int) = NULL;
static int (*func_ioctl)(int, request_t, void *) = NULL;
static int (*func_socket)(int, int, int) = NULL;
static int (*func_bind)(int, const struct sockaddr *, int) = NULL;
static int (*func_write)(int, const void *, size_t) = NULL;
#ifdef CONFIG_LIBNL
static int (*func_nl_send_auto_complete)(struct nl_sock *,
                                         struct nl_msg *) = NULL;
#endif // CONFIG_LIBNL

static long inject_delay_ns = 70000000; // Default 70ms

static void _libmexmon_init() __attribute__((constructor));
static void _libmexmon_init() {
  nexio = nex_init_ioctl(ifname);

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
              inject_delay_ns = 15000000; // 15ms
              // fprintf(stderr, "LIBNEXMON: Auto-detected %s - Setting HIGH SPEED (15ms)\n", proc_name);
          }
          // Airodump-ng: 40ms (Moderate Speed for active scanning)
          else if (strstr(proc_name, "airodump")) {
             inject_delay_ns = 40000000; // 40ms
             // fprintf(stderr, "LIBNEXMON: Auto-detected %s - Setting MONITOR SPEED (40ms)\n", proc_name);
          }
          // Default for unknown tools remains 70ms (Safe Mode)
      }
  }

  if (!func_ioctl)
    func_ioctl = (int (*)(int, request_t, void *))dlsym(REAL_LIBC, "ioctl");

  if (!func_socket)
    func_socket = (int (*)(int, int, int))dlsym(REAL_LIBC, "socket");

  if (!func_bind)
    func_bind =
        (int (*)(int, const struct sockaddr *, int))dlsym(REAL_LIBC, "bind");

  if (!func_write)
    func_write = (int (*)(int, const void *, size_t))dlsym(REAL_LIBC, "write");

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

int handle_nl_msg(struct nl_msg *msg) {
  int retval;
  struct nlmsghdr *nlh;
  struct genlmsghdr *ghdr;
  struct nlattr *attr[NL80211_ATTR_MAX + 1];
  struct nla_policy policy[4] = {
      [0] = {.type = NLA_U32},
  };

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
  if (ghdr->cmd == NL80211_CMD_SET_WIPHY) {
    int chan = 0;
    int ht_mode = NL80211_CHAN_HT20;
    int bandwidth = WL_CHANSPEC_BW_20;
    int band = WL_CHANSPEC_BAND_2G;
    int ctl_sb = 0;

    if (!attr[NL80211_ATTR_IFINDEX])
      return 0;
    if (nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
      return 0;
    // fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n",
    // nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

    if (attr[NL80211_ATTR_WIPHY_FREQ]) {
      int freq = nla_get_u32(attr[NL80211_ATTR_WIPHY_FREQ]);
      chan = frequency_to_channel(freq);
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

    if (chan)
      // nex_set_channel_simple(chan);
      return nex_set_channel_full(chan, band, bandwidth, ctl_sb);
  }
  if (ghdr->cmd == NL80211_CMD_SET_INTERFACE) {
    if (!attr[NL80211_ATTR_IFINDEX])
      return 0;
    if (nla_get_u32(attr[NL80211_ATTR_IFINDEX]) != if_nametoindex(ifname))
      return 0;
    // fprintf(stderr, "NL80211_ATTR_IFINDEX = %u\n",
    // nla_get_u32(attr[NL80211_ATTR_IFINDEX]));

    // we could set monitor/managed mode based on this message
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

  ret = func_nl_send_auto_complete(sk, msg);

  // fprintf(stderr, "\nnl_send_auto_complete()\n");
  ret = handle_nl_msg(msg);
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

  ret = func_ioctl(fd, request, argp);
  // if (ret < 0) {
  //     fprintf(stderr, "LIBNEXMON: original response: %d, request: 0x%x\n",
  //     ret, request);
  // }

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
      else if (buf & MONITOR_DISABLED || buf & MONITOR_LOG_ONLY ||
               buf & MONITOR_DROP_FRM || buf & MONITOR_IPV4_UDP)
        p_ifr->ifr_hwaddr.sa_family = ARPHRD_ETHER;

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

        // Passive enforcement for nexutil-based monitor mode (S10 BCM4375B1)
        // These settings are critical for handshake capture and WPS attacks
        // Errors are ignored to prevent "Operation Not Supported" issues
        int pm = 0; // CAM mode - prevents sleep, crucial for EAPOL/WPS frames
        nex_ioctl(nexio, WLC_SET_PM, &pm, 4, true);

        int promisc = 1; // Ensures we see all packets
        nex_ioctl(nexio, WLC_SET_PROMISC, &promisc, 4, true);
      }

      ret = 0;
    }
  } break;

  case SIOCSIWMODE: {
    int buf;
    struct iwreq *p_wrq = (struct iwreq *)argp;

    if (!strncmp(p_wrq->ifr_ifrn.ifrn_name, ifname, strlen(ifname))) {
      if (p_wrq->u.mode == IW_MODE_MONITOR) {
        buf = MONITOR_RADIOTAP;
        int promisc = 1;
        nex_ioctl(nexio, WLC_SET_PROMISC, &promisc, 4, true);
        int pm = 0; // Disable Power Management (CAM)
        nex_ioctl(nexio, WLC_SET_PM, &pm, 4, true);
      } else {
        buf = MONITOR_DISABLED;
      }

      ret = nex_ioctl(nexio, WLC_SET_MONITOR, &buf, 4, true);
    }
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
      ret = nex_set_channel_simple(channel);

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
  }
  return ret;
}

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

int socket_to_type[65536] = {0};
char bound_to_correct_if[65536] = {0};

int socket(int domain, int type, int protocol) {
  int ret;

  ret = func_socket(domain, type, protocol);

  // save the socket type
  if (ret < sizeof(socket_to_type) / sizeof(socket_to_type[0]))
    socket_to_type[ret] = type;

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

  if ((sockfd < sizeof(bound_to_correct_if) / sizeof(bound_to_correct_if[0])) &&
      !strncmp(ifname, sll_ifname, sizeof(ifname)))
    bound_to_correct_if[sockfd] = 1;

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

  if (inject) {
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

    // Configurable rate-limiting
    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    ret = count;
  } else {
    // otherwise write the regular frame to the socket
    ret = func_write(fd, buf, count);
  }

  return ret;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  ssize_t ret;

  // check if the user wants to write on a raw socket
  int inject = 0;

  // Method 1: Check if socket was bound to correct interface
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
  }

  // Method 2: Check destination address provided in sendto (used by Reaver)
  if (!inject && dest_addr && (sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW)) {
    struct sockaddr_ll *sll = (struct sockaddr_ll *)dest_addr;
    if (sll->sll_ifindex == if_nametoindex(ifname)) {
      inject = 1;
    }
  }

  if (inject) {
    // fprintf(stderr, "sendto(sockfd=%d) -> INJECTION PATH\n", sockfd);

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

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    ret = len;
  } else {
    // otherwise write the regular frame to the socket
    ret = func_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  }

  return ret;
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
  ssize_t ret;
  int inject = 0;

  // Check for injection path - Method 1 (Socket Bound)
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
  }

  // Check for injection path - Method 2 (Destination Interface)
  if (!inject && msg->msg_name && (sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW)) {
    struct sockaddr_ll *sll = (struct sockaddr_ll *)msg->msg_name;
    if (sll->sll_ifindex == if_nametoindex(ifname)) {
      inject = 1;
    }
  }

  // Safety: Ensure iov is valid
  if (inject && (!msg->msg_iov || msg->msg_iovlen == 0)) {
      inject = 0;
  }

  if (inject) {
    // Flatten iovec for injection ioctl
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
        // Copy data from iov
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
        // Copy data from iov
        size_t offset = 0;
        for (size_t i = 0; i < msg->msg_iovlen; i++) {
           memcpy(buf_dup->data + offset, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
           offset += msg->msg_iov[i].iov_len;
        }
        nex_ioctl(nexio, NEX_INJECT_FRAME, buf_dup, frame_len, true);
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    ret = total_len;
  } else {
    ret = func_sendmsg(sockfd, msg, flags);
  }

  return ret;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
  ssize_t ret;
  int inject = 0;

  // Check for injection path
  if ((sockfd > 2) &&
      (sockfd < sizeof(socket_to_type) / sizeof(socket_to_type[0])) &&
      (socket_to_type[sockfd] == SOCK_RAW) &&
      (bound_to_correct_if[sockfd] == 1)) {
    inject = 1;
  }

  if (inject) {
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

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    ret = len;
  } else {
    ret = func_send(sockfd, buf, len, flags);
  }
  return ret;
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
  int ret;
  int inject = 0;

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

  if (inject) {
    // Inject each message individually
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

        // Allow checking result for each, or just count as sent
        msgvec[i].msg_len = total_len;
    }

    if (inject_delay_ns > 0) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = inject_delay_ns;
        nanosleep(&ts, NULL);
    }

    ret = vlen;
  } else {
    ret = func_sendmmsg(sockfd, msgvec, vlen, flags);
  }
  return ret;
}
