/* Host harness for the TicWatch Pro 3 lane in nexmon.c.
 *
 * Compiled with -DARCH_ARMHF, so the #if defined(ARCH_ARMHF) blocks under test
 * are the ones the watch build gets. The shim is included as source, so these
 * are the real functions, not a reimplementation, and the libnexio entry
 * points are stubbed out with a fake firmware that can be told what to answer.
 *
 * Including nexmon.c also means its constructor runs before main(), which is
 * what sets up nexio and resolves func_ioctl through dlsym — the tests below
 * rely on that having happened.
 *
 * Build (from the repository root):
 *   gcc -std=c99 -I. -I/usr/include/libnl3 -DARCH_ARMHF -Wall \
 *       -o /tmp/twp3_lane_test tests/twp3_lane_test.c -ldl -lnl-3 -lnl-genl-3
 *
 * What it checks, in order:
 *   1. the lane probe, against a firmware that answers 400 (watch), one that
 *      rejects it (S10), one that answers nothing, and NEXMON_INJECT=...
 *   2. the radiotap preamble the watch's wl_send_hook gates on, through the
 *      real write() hook and end to end (a pipe stands in for the socket)
 *   3. every transmit wrapper's byte layout: bare frame, frame that already
 *      carries radiotap, split iovecs, oversized frame, preamble disabled
 *   4. the diagnostics: counters, the log file, and the verdict
 *   5. the SIOCSIWMODE path airodump-ng takes, including the interface-name
 *      mismatch that used to be silent
 */

/* nexmon.c first: it is the translation unit the real build sees, and its
 * includes set up the headers exactly as they are on the device. */
#include "nexmon.c"

#include <unistd.h>   /* pipe(), close() for the end-to-end check */

#define TEST_LOG "/tmp/nexmon_test.log"

/* ── fake firmware ─────────────────────────────────────────────────────── */
static int fw_answers_caps = 1;      /* does the firmware implement command 400? */
static int fw_caps_value = 7;        /* NEX_CAP_* bits it reports */
static int fw_answers_monitor = 1;   /* does WLC_GET_MONITOR answer? */
static int fw_monitor_state = 0;     /* what WLC_GET_MONITOR reports */

/* Every write that would re-programme the radio. On the watch these are the
 * calls that crash the firmware when they are redundant, so the tests below
 * assert on the count rather than on the return value. */
static int fw_monitor_writes = 0;
static int fw_promisc_writes = 0;
static int fw_pm_writes = 0;

struct nexio *nex_init_ioctl(const char *name) {
  static struct nexio n;
  (void)name;
  memset(&n, 0, sizeof(n));
  n.ifr = (struct ifreq *)&n; /* the constructor only tests this for NULL */
  return &n;
}

int nex_ioctl(struct nexio *nx, int cmd, void *buf, int len, bool set) {
  (void)nx; (void)len;
  switch (cmd) {
  case NEX_GET_CAPABILITIES:
    if (!fw_answers_caps) return -1;
    *(int *)buf = fw_caps_value;
    return 0;
  case WLC_GET_MONITOR:
    if (!fw_answers_monitor) return -1;
    *(int *)buf = fw_monitor_state;
    return 0;
  case WLC_SET_MONITOR:
    if (set) fw_monitor_writes++;
    return 0;
  case WLC_SET_PROMISC:
    if (set) fw_promisc_writes++;
    return 0;
  case WLC_SET_PM:
    if (set) fw_pm_writes++;
    return 0;
  case WLC_GET_VAR:
    snprintf((char *)buf, 64, "9.88.4.65 (r745790)");
    return 0;
  }
  return 0;
}

/* ── harness ───────────────────────────────────────────────────────────── */
static int fails = 0;

static void check(const char *what, int ok) {
  fprintf(stderr, "%s  %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) fails++;
}

static const unsigned char RTAP8[8] = {0, 0, 8, 0, 0, 0, 0, 0};

/* A frame the watch firmware will inject: its first two bytes are zero and it
 * says the radiotap header is 8 bytes long. */
static int is_preamble(const unsigned char *b, size_t len) {
  size_t i;
  if (len < 8) return 0;
  for (i = 0; i < 8; i++)
    if (b[i] != RTAP8[i]) return 0;
  return 1;
}

/* ── capture stubs for the real send functions ─────────────────────────── */
static unsigned char cap[8192];
static size_t cap_len;
static ssize_t ftx_last;    /* what the stub returned */
static int cap_calls;

static ssize_t capture(const void *buf, size_t len) {
  memcpy(cap, buf, len > sizeof(cap) ? sizeof(cap) : len);
  cap_len = len;
  cap_calls++;
  return ftx_last;
}

static ssize_t stub_write(int fd, const void *b, size_t n) { (void)fd; return capture(b, n); }
/* nexmon.c declares func_sendto as returning int, so the stub matches that. */
static int stub_sendto(int fd, const void *b, size_t n, int f,
                       const struct sockaddr *a, socklen_t al) {
  (void)fd; (void)f; (void)a; (void)al; return (int)capture(b, n);
}
static ssize_t stub_send(int fd, const void *b, size_t n, int f) { (void)fd; (void)f; return capture(b, n); }
static ssize_t stub_sendmsg(int fd, const struct msghdr *m, int f) {
  size_t off = 0;
  (void)fd; (void)f;
  for (size_t i = 0; i < m->msg_iovlen; i++) {
    memcpy(cap + off, m->msg_iov[i].iov_base, m->msg_iov[i].iov_len);
    off += m->msg_iov[i].iov_len;
  }
  cap_len = off;
  cap_calls++;
  return ftx_last;
}
static int stub_sendmmsg(int fd, struct mmsghdr *v, unsigned int n, int f) {
  int sent = 0;
  (void)fd; (void)f;
  for (unsigned int i = 0; i < n; i++) {
    struct msghdr *m = &v[i].msg_hdr;
    size_t off = 0;
    for (size_t j = 0; j < m->msg_iovlen; j++) {
      memcpy(cap + off, m->msg_iov[j].iov_base, m->msg_iov[j].iov_len);
      off += m->msg_iov[j].iov_len;
    }
    cap_len = off;
    v[i].msg_len = (unsigned int)off;
    cap_calls++;
    sent++;
  }
  return sent;
}

static void reset_capture(ssize_t ret) {
  cap_len = 0;
  cap_calls = 0;
  ftx_last = ret;
  memset(cap, 0xAA, sizeof(cap));
}

/* Stands in for libnl's send: counts what actually left, which is how the
 * tests tell a faked request from a sent one. The real function also fills in
 * the sequence number the reply will quote (nl_complete_msg does that at send
 * time, not at build time), so this one does too. */
static int nl_sent_calls = 0;
static unsigned stub_seq_next = 1000;
static int stub_sendmsg_nl(struct nl_sock *sk, struct nl_msg *msg) {
  (void)sk;
  nl_sent_calls++;
  nlmsg_hdr(msg)->nlmsg_seq = stub_seq_next++;
  return (int)nlmsg_total_size(nlmsg_datalen(nlmsg_hdr(msg)));
}

/* And for libnl's wait: reaching this means the hook did not answer locally,
 * which is the difference between "answered" and "blocked for ever". */
static int nl_last_acked = 0;
static int stub_wait_nl(struct nl_sock *sk) { (void)sk; nl_last_acked++; return 0; }

/* ── 1. the lane probe ─────────────────────────────────────────────────── */
static void test_probe(void) {
  unsetenv("NEXMON_INJECT");
  unsetenv("NEXMON_DEBUG");

  fw_answers_caps = 1; fw_answers_monitor = 1; fw_caps_value = 7;
  nex_detect_injection_method();
  check("watch firmware (answers 400) -> raw lane",
        current_inject_method == INJECT_RAW_SOCKET);

  fw_answers_caps = 0; fw_answers_monitor = 1;
  nex_detect_injection_method();
  check("S10 firmware (rejects 400, monitor answers) -> ioctl lane",
        current_inject_method == INJECT_IOCTL);

  fw_answers_caps = 0; fw_answers_monitor = 0;
  nex_detect_injection_method();
  check("probe inconclusive on armhf -> raw lane",
        current_inject_method == INJECT_RAW_SOCKET);

  /* anything 400 is answered with is enough — even without the capability bit */
  fw_answers_caps = 1; fw_answers_monitor = 0; fw_caps_value = 1;
  nex_detect_injection_method();
  check("firmware answering 400 without the caps bit -> raw lane",
        current_inject_method == INJECT_RAW_SOCKET);

  fw_answers_caps = 0; fw_answers_monitor = 1;
  setenv("NEXMON_INJECT", "raw", 1);
  nex_detect_injection_method();
  check("NEXMON_INJECT=raw overrides the probe",
        current_inject_method == INJECT_RAW_SOCKET);

  fw_answers_caps = 1;
  setenv("NEXMON_INJECT", "IOCTL", 1);
  nex_detect_injection_method();
  check("NEXMON_INJECT=ioctl overrides the probe (case-insensitive)",
        current_inject_method == INJECT_IOCTL);

  unsetenv("NEXMON_INJECT");
}

/* ── 2. the real write() hook, end to end ──────────────────────────────── */
static void test_write_hook(void) {
  int p[2];
  unsigned char frame[24];
  unsigned char got[256];
  ssize_t n, g;

  memset(frame, 0, sizeof(frame));
  frame[0] = 0x80; /* beacon frame control */
  frame[4] = 0xff; frame[5] = 0xff; frame[6] = 0xff; /* broadcast */
  frame[7] = 0xff; frame[8] = 0xff; frame[9] = 0xff;

  if (pipe(p) != 0) { check("pipe() for the write() test", 0); return; }

  current_inject_method = INJECT_RAW_SOCKET;
  inject_delay_ns = 0;
  nex_radiotap_disabled = 0;
  socket_to_type[p[1]] = SOCK_RAW; /* what the socket() hook records on a raw socket */

  n = write(p[1], frame, sizeof(frame));
  g = func_read(p[0], got, sizeof(got));

  check("write() tells the tool it wrote its frame (not the preamble too)",
        n == (ssize_t)sizeof(frame));
  check("write() put preamble + frame on the wire",
        g == (ssize_t)(8 + sizeof(frame)));
  check("that preamble is it_version 0, it_pad 0, it_len 8",
        g >= 8 && memcmp(got, RTAP8, 8) == 0);
  check("the frame behind it is untouched",
        g >= (ssize_t)(8 + sizeof(frame)) &&
            memcmp(got + 8, frame, sizeof(frame)) == 0);

  /* a tool that builds its own radiotap must not get a second header */
  {
    unsigned char rtap13[13] = {0, 0, 13, 0, 0x00, 0x00, 0x80, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char buf[64];
    memcpy(buf, rtap13, 13);
    memcpy(buf + 13, frame, sizeof(frame));

    socket_to_type[p[1]] = SOCK_RAW;
    n = write(p[1], buf, 13 + sizeof(frame));
    g = func_read(p[0], got, sizeof(got));
    check("radiotap-bearing frame passes through unsingled",
          g == (ssize_t)(13 + sizeof(frame)) && memcmp(got, buf, 13 + sizeof(frame)) == 0);
    check("  and its return is still the caller's count",
          n == (ssize_t)(13 + sizeof(frame)));
  }

  /* an oversized frame cannot be copied — it must go out as it is, not vanish */
  {
    static unsigned char big[MAX_INJECT_BUF + 64];
    memset(big, 0, sizeof(big));
    big[0] = 0x80;
    socket_to_type[p[1]] = SOCK_RAW;
    n = write(p[1], big, sizeof(big));
    check("oversized frame is still written (uncopied)", n == (ssize_t)sizeof(big));
  }

  close(p[0]);
  close(p[1]);
}

/* ── 3. the transmit wrappers ──────────────────────────────────────────── */
static void test_wrappers(void) {
  unsigned char frame[24];


  memset(frame, 0, sizeof(frame));
  frame[0] = 0x80;

  current_inject_method = INJECT_RAW_SOCKET;
  nex_radiotap_disabled = 0;

  reset_capture(1024);
  check("nex_raw_write returns the caller's count on success",
        nex_raw_write(1, frame, sizeof(frame)) == (ssize_t)sizeof(frame));
  check("nex_raw_write wrote preamble + frame",
        cap_len == 8 + sizeof(frame) && is_preamble(cap, cap_len) &&
            memcmp(cap + 8, frame, sizeof(frame)) == 0);

  reset_capture(1024);
  nex_raw_sendto(1, frame, sizeof(frame), 0, NULL, 0);
  check("nex_raw_sendto wrote preamble + frame",
        cap_len == 8 + sizeof(frame) && is_preamble(cap, cap_len));

  reset_capture(1024);
  nex_raw_send(1, frame, sizeof(frame), 0);
  check("nex_raw_send wrote preamble + frame",
        cap_len == 8 + sizeof(frame) && is_preamble(cap, cap_len));

  /* split frame: the iovecs are flattened behind one preamble */
  {
    struct iovec iov[2] = {{.iov_base = frame, .iov_len = 10},
                           {.iov_base = frame + 10, .iov_len = 14}};
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    reset_capture(1024);
    check("nex_raw_sendmsg reports the caller's count",
          nex_raw_sendmsg(1, &msg, 0) == 24);
    check("nex_raw_sendmsg flattened the iovecs behind one preamble",
          cap_len == 8 + 24 && is_preamble(cap, cap_len) &&
              memcmp(cap + 8, frame, 24) == 0);

    /* sendmmsg: one message, same layout, and msg_len set on the way out */
    {
      struct mmsghdr mm;
      memset(&mm, 0, sizeof(mm));
      mm.msg_hdr.msg_iov = iov;
      mm.msg_hdr.msg_iovlen = 2;

      reset_capture(1024);
      check("nex_raw_sendmmsg sent the one message",
            nex_raw_sendmmsg(1, &mm, 1, 0) == 1);
      check("nex_raw_sendmmsg flattened the iovecs behind one preamble",
            cap_len == 8 + 24 && is_preamble(cap, cap_len) &&
                memcmp(cap + 8, frame, 24) == 0);
      check("nex_raw_sendmmsg reports the caller's byte count in msg_len",
            mm.msg_len == 24);
    }
  }

  /* a single iovec that already carries radiotap goes through sendmsg intact */
  {
    unsigned char buf[37];
    struct iovec iov = {.iov_base = buf, .iov_len = sizeof(buf)};
    struct msghdr msg;
    memset(buf, 0, sizeof(buf));
    buf[2] = 13; /* it_len */
    buf[13] = 0x80;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    reset_capture(1024);
    nex_raw_sendmsg(1, &msg, 0);
    check("nex_raw_sendmsg passes an existing radiotap header straight through",
          cap_len == sizeof(buf) && memcmp(cap, buf, sizeof(buf)) == 0);
  }

  /* the same header, but the tool split header and body across two iovecs */
  {
    unsigned char hdr[8] = {0, 0, 8, 0, 0, 0, 0, 0};
    unsigned char body[24];
    struct iovec iov[2] = {{.iov_base = hdr, .iov_len = sizeof(hdr)},
                           {.iov_base = body, .iov_len = sizeof(body)}};
    struct msghdr msg;
    memset(body, 0, sizeof(body));
    body[0] = 0x80;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    reset_capture(1024);
    nex_raw_sendmsg(1, &msg, 0);
    check("a header split into its own iovec is not doubled",
          cap_len == sizeof(hdr) + sizeof(body) && memcmp(cap, hdr, 8) == 0 &&
              memcmp(cap + 8, body, sizeof(body)) == 0);
  }

  /* NEXMON_RAW_NO_RADIOTAP=1 */
  {
    nex_radiotap_disabled = 1;
    reset_capture(1024);
    nex_raw_write(1, frame, sizeof(frame));
    check("with the preamble disabled the frame goes out as it is",
          cap_len == sizeof(frame) && memcmp(cap, frame, sizeof(frame)) == 0);
    nex_radiotap_disabled = 0;
  }

  /* failure propagates untouched */
  reset_capture(-1);
  check("a failing write is reported as it came back",
        nex_raw_write(1, frame, sizeof(frame)) == -1);
}

/* ── 4. the diagnostics themselves ─────────────────────────────────────── */
static char *slurp(const char *path) {
  static char buf[65536];
  size_t n;
  FILE *f = fopen(path, "r");
  if (!f) return NULL;
  n = fread(buf, 1, sizeof(buf) - 1, f);
  fclose(f);
  buf[n] = 0;
  return buf;
}

static void test_diagnostics(void) {
  unsigned char bare[24], rtap[32];
  const char *log;
  int fd = 5;
  unsigned long ok_before, added_before, kept_before;

  current_inject_method = INJECT_RAW_SOCKET;
  nex_radiotap_disabled = 0;
  inject_delay_ns = 0;

  fw_answers_caps = 1; fw_answers_monitor = 1; fw_caps_value = 7;
  nex_detect_injection_method();

  socket_to_type[fd] = SOCK_RAW;
  bound_to_correct_if[fd] = 1;

  /* the counters are process-wide, so compare against a snapshot taken here
   * rather than asserting an absolute number */
  ok_before = nex_tx_ok;
  added_before = nex_rtap_added;
  kept_before = nex_rtap_kept;

  memset(bare, 0, sizeof(bare));
  bare[0] = 0x80;
  reset_capture(1024);
  write(fd, bare, sizeof(bare));

  memset(rtap, 0, sizeof(rtap));
  rtap[2] = 8;                 /* it_len */
  rtap[8] = 0x80;
  reset_capture(1024);
  write(fd, rtap, sizeof(rtap));

  /* a write that is not injection at all — must be explained, not silent */
  reset_capture(1024);
  write(1, bare, sizeof(bare));

  nex_dump_summary();

  check("both injections were counted as successful",
        nex_tx_ok - ok_before == 2);
  check("the bare frame had a preamble added",
        nex_rtap_added - added_before == 1);
  check("the radiotap-bearing frame was left alone",
        nex_rtap_kept - kept_before == 1);

  log = slurp(TEST_LOG);
  check("diagnostics write a log file", log != NULL);
  if (!log) return;
  check("  the lane probe is recorded",
        strstr(log, "NEX_GET_CAPABILITIES(400)") != NULL);
  check("  the frame given the preamble is recorded in the log",
        strstr(log, "write(fd=5, 24 B) INJECT") != NULL);
  check("  the frame that already had radiotap is recorded in the log",
        strstr(log, "write(fd=5, 32 B) INJECT") != NULL);
  check("  a non-injection write is explained",
        strstr(log, "fd is a standard stream") != NULL);
  check("  the tally reports successes", strstr(log, "ok=") != NULL);
  check("  the tally names the process", strstr(log, "(pid ") != NULL);
  check("  a VERDICT is printed", strstr(log, "VERDICT:") != NULL);
  check("  the verdict identifies the right outcome",
        strstr(log, "frames were handed to the kernel") != NULL);
}

/* ── 5. the SIOCSIWMODE path airodump-ng takes ─────────────────────────── */
static int drv_ioctl_calls = 0;
static int drv_ioctl_last_req = 0;

/* Stands in for the kernel on the watch: it has no monitor mode to offer, and
 * on the real device this is the call that takes the firmware down. */
static int stub_ioctl(int fd, request_t request, void *arg) {
  (void)fd; (void)arg;
  drv_ioctl_calls++;
  drv_ioctl_last_req = (int)request;
  return -1;
}

static void test_ioctl_monitor(void) {
  struct iwreq wrq;
  unsigned long set_before, seen_before;
  const char *log;
  int ret;

  func_ioctl = stub_ioctl;

  /* An interface this library is not watching: forwarded as before, because a
   * call for somebody else's interface is not ours to answer. */
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_ifrn.ifrn_name, "wlan9", IFNAMSIZ - 1);
  wrq.u.mode = IW_MODE_MONITOR;

  set_before = nex_mon_set;
  seen_before = nex_ioctl_seen;
  drv_ioctl_calls = 0;
  ioctl(-1, SIOCSIWMODE, &wrq);

  check("SIOCSIWMODE on an interface we do not watch sets no radio state",
        nex_mon_set == set_before);
  check("  but the hook was entered, so it is not silently skipped",
        nex_ioctl_seen == seen_before + 1);
  check("  and it is still passed to the driver, whose interface it is",
        drv_ioctl_calls == 1 && drv_ioctl_last_req == SIOCSIWMODE);

  /* The interface we do watch. This is the call that killed the firmware: the
   * driver answers it by going down into the chip, and the tool is asking for a
   * monitor mode that is already on. It must not be forwarded, and the handler
   * must not write radio state either. */
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_ifrn.ifrn_name, "wlan0", IFNAMSIZ - 1);
  wrq.u.mode = IW_MODE_MONITOR;

  set_before = nex_mon_set;
  drv_ioctl_calls = 0;
  fw_monitor_writes = fw_promisc_writes = fw_pm_writes = 0;
  ret = ioctl(-1, SIOCSIWMODE, &wrq);

  check("SIOCSIWMODE on wlan0 is handled", nex_mon_set == set_before + 1);
  check("the driver never sees it — this is the call that crashed the firmware",
        drv_ioctl_calls == 0);
  check("no WLC_SET_MONITOR re-enable is issued", fw_monitor_writes == 0);
  check("  and no promiscuous or power-management writes either",
        fw_promisc_writes == 0 && fw_pm_writes == 0);
  check("the tool is told it succeeded, so it does not abort", ret == 0);

  /* The other direction is the same shape: a tool resetting the interface to
   * managed partway through startup must not tear down the monitor mode that
   * was set from Android. */
  wrq.u.mode = IW_MODE_INFRA;
  drv_ioctl_calls = 0;
  fw_monitor_writes = 0;
  ret = ioctl(-1, SIOCSIWMODE, &wrq);

  check("a request for managed mode is also left alone", fw_monitor_writes == 0);
  check("  and is not forwarded to the driver", drv_ioctl_calls == 0);
  check("  and is reported as success", ret == 0);

  log = slurp(TEST_LOG);
  check("the mismatch is logged rather than passed over in silence",
        log && strstr(log, "ignored — this library watches \"wlan0\"") != NULL);
  check("the radio-left-alone decision is logged with the firmware's real state",
        log && strstr(log, "radio left alone, reporting success") != NULL);
}

/* ── 6. Kismet's netlink lane ──────────────────────────────────────────── */
/* What kismet_cap_linux_wifi does through libnl: asks for monitor mode, waits
 * for the ACK of that request — the wait is where libnl produces the error, so
 * a faked send with no ACK behind it blocks the helper for ever — sets a
 * channel, and tries to create a monitor vif it has to be told no about. */

/* A parsed SET_WIPHY / SET_INTERFACE / NEW_INTERFACE message, built the way
 * libnl builds one — nlmsg_hdr() reaches into the struct nl_msg, so a bare
 * nlmsghdr buffer would be read at the wrong offset. */
static unsigned nl_last_seq;

static struct nl_msg *nl_build(unsigned char cmd, int attrtype, unsigned val,
                               const char *s) {
  struct nl_msg *msg = nlmsg_alloc();

  if (!msg)
    return NULL;
  if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl80211_type(), 0, 0, cmd, 0))
    goto fail;
  if (s) {
    if (nla_put_string(msg, attrtype, s) < 0)
      goto fail;
  } else if (nla_put_u32(msg, attrtype, val) < 0) {
    goto fail;
  }
  return msg;

fail:
  nlmsg_free(msg);
  return NULL;
}

/* Send it and let it go — the hook does not take ownership. */
static void nl_send_fake(unsigned char cmd, int attrtype, unsigned val,
                         const char *s) {
  struct nl_msg *msg = nl_build(cmd, attrtype, val, s);
  if (!msg) {
    check("built the libnl message under test", 0);
    return;
  }
  nl_send_auto_complete((struct nl_sock *)0x1234, msg);
  /* libnl's own sequence counter, read after the hook has remembered it — the
   * reply below has to quote the number the request actually left with. */
  nl_last_seq = nlmsg_hdr(msg)->nlmsg_seq;
  nlmsg_free(msg);
}

/* A reply, delivered the way libnl delivers one: a single iovec, possibly
 * preceded by an unrelated message, so the walk has to step over it. */
static unsigned char nl_reply[256];
static struct iovec nl_reply_iov;
static struct msghdr nl_reply_msg;

static size_t nl_reply_error(int nlerr, unsigned seq, int lead) {
  struct nlmsghdr *nlh = (struct nlmsghdr *)nl_reply;
  struct nlmsgerr *e;
  size_t off = 0;

  memset(nl_reply, 0, sizeof(nl_reply));
  if (lead) { /* a message of another kind in front of it */
    struct nlmsghdr *l = (struct nlmsghdr *)nl_reply;
    l->nlmsg_len = NLMSG_HDRLEN + 4;
    l->nlmsg_type = 16; /* a genl family id, not an error */
    off = NLMSG_ALIGN(l->nlmsg_len);
  }

  nlh = (struct nlmsghdr *)(nl_reply + off);
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nlmsgerr));
  nlh->nlmsg_type = NLMSG_ERROR;
  nlh->nlmsg_seq = seq + 1; /* the reply's own sequence is its own */
  e = (struct nlmsgerr *)NLMSG_DATA(nlh);
  e->error = nlerr;
  e->msg.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
  e->msg.nlmsg_type = (unsigned short)nl80211_type();
  e->msg.nlmsg_seq = seq; /* the rejected request's sequence — the only link */
  off += NLMSG_ALIGN(nlh->nlmsg_len);

  nl_reply_iov.iov_base = nl_reply;
  nl_reply_iov.iov_len = off;
  memset(&nl_reply_msg, 0, sizeof(nl_reply_msg));
  nl_reply_msg.msg_iov = &nl_reply_iov;
  nl_reply_msg.msg_iovlen = 1;
  return off;
}

static int nl_reply_error_of(void) {
  struct nlmsghdr *nlh = (struct nlmsghdr *)(nl_reply + NLMSG_ALIGN(0));
  /* step to the message that is an error, wherever it landed */
  while (nlh->nlmsg_type != NLMSG_ERROR)
    nlh = (struct nlmsghdr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
  return ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
}

/* Stands in for the kernel's recvmsg(): hands back the prepared reply. */
static ssize_t stub_recvmsg(int fd, struct msghdr *msg, int flags) {
  ssize_t n = (ssize_t)nl_reply_iov.iov_len;
  (void)fd; (void)flags;
  memcpy(msg->msg_iov[0].iov_base, nl_reply, (size_t)n);
  return n;
}

static void test_kismet_netlink(void) {
  int sent_before;

  func_sendmsg = stub_sendmsg;
  func_nl_send_auto_complete = stub_sendmsg_nl;
  func_recvmsg = stub_recvmsg;
  func_nl_wait_for_ack = stub_wait_nl;
  is_kismet = 1;

  /* A netlink socket has to be tracked as one for any of this to apply. */
  socket_to_type[7] = SOCK_RAW;
  socket_is_netlink[7] = 1;

  /* 1. the fake must be armed, and the wait that follows must not reach libc:
   * with nothing sent, the real nl_wait_for_ack() never returns. */
  nl_sent_calls = 0;
  nl_last_acked = 0;
  nl_send_fake(NL80211_CMD_SET_INTERFACE, NL80211_ATTR_IFTYPE,
               NL80211_IFTYPE_MONITOR, NULL);
  check("a SET_INTERFACE request is faked, not sent", nl_sent_calls == 0);
  check("nl_wait_for_ack() answers it instead of blocking",
        nl_wait_for_ack((struct nl_sock *)0x1234) == 0);
  check("  and the wait never reaches libnl's own function",
        nl_last_acked == 0);
  check("  and the second wait is handed to libnl as usual",
        (nl_wait_for_ack((struct nl_sock *)0x1234), nl_last_acked == 1));

  /* 2. a channel set the kernel refuses is rewritten, because the library
   * performs this one itself — and only when the sequence number says the
   * reply belongs to it. */
  nl_send_fake(NL80211_CMD_SET_WIPHY, NL80211_ATTR_WIPHY_FREQ, 2437, NULL);
  sent_before = nl_sent_calls;
  check("the channel-set request does reach libnl", sent_before == 1);

  nl_reply_error(-22, nl_last_seq, 0);
  nex_nl_scrub(&nl_reply_msg, (ssize_t)nl_reply_iov.iov_len);
  check("a refused channel set is rewritten to success", nl_reply_error_of() == 0);

  /* the same error, for a request this library did not answer for */
  nl_reply_error(-22, nl_last_seq + 1, 0);
  nex_nl_scrub(&nl_reply_msg, (ssize_t)nl_reply_iov.iov_len);
  check("an error for another sequence number is left alone",
        nl_reply_error_of() == -22);

  /* and a command this library must never paper over: Kismet has to see the
   * monitor vif creation fail, or it captures from a vif that is not there. */
  nl_send_fake(NL80211_CMD_NEW_INTERFACE, NL80211_ATTR_IFNAME, 0, "wlan0mon");
  nl_reply_error(-22, nl_last_seq, 0);
  nex_nl_scrub(&nl_reply_msg, (ssize_t)nl_reply_iov.iov_len);
  check("a refused NEW_INTERFACE is NOT rewritten — Kismet must fall back",
        nl_reply_error_of() == -22);

  /* 3. the reply arrives through recvmsg(), which is the whole point: the
   * read() hook is not on this path. */
  nl_send_fake(NL80211_CMD_SET_WIPHY, NL80211_ATTR_WIPHY_FREQ, 2437, NULL);
  nl_reply_error(-22, nl_last_seq, 1); /* with an unrelated message in front of it */
  nex_rx_msg_netlink = 0;
  nex_recvmsg_plain(7, &nl_reply_msg, 0);
  check("recvmsg() sees the netlink socket", nex_rx_msg_netlink == 1);
  check("  and steps past the leading message to rewrite the right one",
        nl_reply_error_of() == 0);

  /* not a netlink socket -> the reply is not ours to touch */
  nl_reply_error(-22, nl_last_seq, 0);
  socket_is_netlink[7] = 0;
  nex_recvmsg_plain(7, &nl_reply_msg, 0);
  check("a reply on a non-netlink socket is untouched",
        nl_reply_error_of() == -22);
  socket_is_netlink[7] = 1;

  is_kismet = 0;
}

int main(void) {
  inject_delay_ns = 0;

  /* Resolve the nl80211 family id before any test replaces libnl's send/recv
   * entry points. nl80211_type() performs a real genl lookup on first use, and
   * that lookup sends and receives through the very hooks the Kismet test
   * stubs out; running it afterwards would leave libnl waiting for a reply the
   * stub never sent. On the watch the id is likewise resolved once, by the
   * library, before any tool traffic. */
  if (nl80211_type() <= 0) {
    fprintf(stderr, "cannot resolve the nl80211 generic-netlink family on this "
                    "host; the netlink checks need a kernel that has it\n");
    return 1;
  }

  fprintf(stderr, "── lane probe\n");
  test_probe();

  /* this one runs against the real libc write()/read(), with a pipe standing
   * in for the socket, so the bytes really travel */
  fprintf(stderr, "── write() hook, end to end\n");
  test_write_hook();

  /* from here on the transmit calls are captured instead of sent */
  func_write = stub_write;
  func_sendto = stub_sendto;
  func_send = stub_send;
  func_sendmsg = stub_sendmsg;
  func_sendmmsg = stub_sendmmsg;

  fprintf(stderr, "── transmit wrappers\n");
  test_wrappers();

  /* turn the diagnostics on for the remaining two, so they can be read back */
  unlink(TEST_LOG);
  setenv("NEXMON_DEBUG", "2", 1);
  setenv("NEXMON_LOG", TEST_LOG, 1);
  nex_diag_init();

  fprintf(stderr, "── diagnostics\n");
  test_diagnostics();

  fprintf(stderr, "── ioctl monitor-mode path\n");
  test_ioctl_monitor();

  fprintf(stderr, "── kismet netlink lane\n");
  test_kismet_netlink();

  unsetenv("NEXMON_DEBUG");
  unsetenv("NEXMON_LOG");

  fprintf(stderr, "\n%s (%d failure%s)\n", fails ? "FAILED" : "all good", fails,
          fails == 1 ? "" : "s");
  return fails ? 1 : 0;
}
