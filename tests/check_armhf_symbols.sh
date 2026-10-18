#!/bin/sh
# Guard for the one failure on this lane that no other test can see: a hook
# that is compiled, correct, and never entered — because the tool and the
# library disagree about the symbol's name.
#
# A 32-bit-time glibc hands callers the __*_time64 spelling of ioctl, sendmsg
# and sendmmsg as soon as they are built with _TIME_BITS=64 / _FILE_OFFSET_BITS=64,
# which is the armhf default. The rename is an assembler label on glibc's own
# declaration, so it shows up in the tool's symbol table and nowhere in our
# source; the library exports both spellings to cover it. See the
# __ioctl_time64 note in nexmon.c.
#
# On the watch this was the whole of "Error setting monitor mode on wlan0":
# airodump-ng's SIOCGIFHWADDR/SIOCGIWMODE/SIOCSIWMODE calls all went straight
# to the kernel, every ioctl counter stayed at zero, and airodump-ng aborted.
#
# Usage: tests/check_armhf_symbols.sh [libnexmonkali-armhf.so]
set -e

NM=${NM:-arm-linux-gnueabihf-nm}
SO=${1:-libnexmonkali-armhf.so}

if [ ! -f "$SO" ]; then
  echo "no $SO — run 'make armhf' first" >&2
  exit 1
fi

# Reading the wrong architecture's object would report every name as missing,
# which looks exactly like the bug this guards against.
if ! $NM -D --defined-only "$SO" >/dev/null 2>&1; then
  echo "$SO is not a 32-bit ARM object $NM can read (aarch64 build?)" >&2
  exit 1
fi

fails=0
syms=$($NM -D --defined-only "$SO" | awk '{print $3}')

addr_of() {
  $NM -D --defined-only "$SO" | awk -v n="$1" '$3 == n { print $1; exit }'
}

for pair in ioctl:__ioctl_time64 sendmsg:__sendmsg64 sendmmsg:__sendmmsg64 \
            recvmsg:__recvmsg64 setsockopt:__setsockopt64; do
  plain=${pair%%:*}
  wide=${pair##*:}

  for name in "$plain" "$wide"; do
    if printf '%s\n' "$syms" | grep -qx "$name"; then
      printf 'ok    %s\n' "$name"
    else
      printf 'MISS  %s — a tool calling this name reaches the kernel, not the firmware\n' "$name"
      fails=$((fails + 1))
    fi
  done

  # Both names must be the same function: an alias, not a second implementation
  # that could drift away from the one the tests exercise.
  a=$(addr_of "$plain" || true)
  b=$(addr_of "$wide" || true)
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    printf 'ok    %s and %s are one function at %s\n' "$plain" "$wide" "$a"
  elif [ -n "$a" ] && [ -n "$b" ]; then
    printf 'MISS  %s (%s) and %s (%s) are different functions\n' "$plain" "$a" "$wide" "$b"
    fails=$((fails + 1))
  fi
done

if [ "$fails" -ne 0 ]; then
  echo "FAILED ($fails)" >&2
  exit 1
fi
echo "all hook spellings exported"
