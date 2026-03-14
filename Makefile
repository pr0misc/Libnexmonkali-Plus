# Libnexmonkali-Plus Build System
# Universal build for ARM64 (aarch64) and ARM32 (armhf) devices

# ─── Toolchains ───────────────────────────────────────────────────
CC_AARCH64  = aarch64-linux-gnu-gcc
AR_AARCH64  = aarch64-linux-gnu-ar
CC_ARMHF    = arm-linux-gnueabihf-gcc
AR_ARMHF    = arm-linux-gnueabihf-ar

# Default to aarch64
CC = $(CC_AARCH64)
AR = $(AR_AARCH64)

# ─── Architecture Flags ──────────────────────────────────────────
# These defines let the library know its target arch at compile time
# ARCH_AARCH64: 64-bit ARM (Samsung S10/S21, modern Android, RPi 64-bit)
# ARCH_ARMHF:   32-bit ARM (TicWatch, RPi 32-bit, older Android)
ARCH_FLAGS =

# ─── Common Flags ────────────────────────────────────────────────
CFLAGS  = -std=c99 -I./ -I/usr/include/libnl3 $(ARCH_FLAGS)
LDFLAGS = -shared -fPIC -ldl

# ─── Targets ─────────────────────────────────────────────────────

# Default: build aarch64
all: aarch64

# 64-bit ARM build (Samsung S10/S21+, modern phones, RPi 64-bit)
aarch64: CC = $(CC_AARCH64)
aarch64: AR = $(AR_AARCH64)
aarch64: ARCH_FLAGS = -DARCH_AARCH64
aarch64: clean _build
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo " ✅ Built for AARCH64 (64-bit ARM)"
	@echo " Devices: Samsung S10/S21+, modern phones, RPi 64-bit"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 32-bit ARM build (TicWatch, RPi 32-bit, older Android)
armhf: CC = $(CC_ARMHF)
armhf: AR = $(AR_ARMHF)
armhf: ARCH_FLAGS = -DARCH_ARMHF
armhf: clean _build
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo " ✅ Built for ARMHF (32-bit ARM)"
	@echo " Devices: TicWatch Pro, RPi 32-bit, older Android"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─── Internal Build Rules ────────────────────────────────────────
_build: libnexio.a libnexmonkali.so

libnexmonkali.so: libnexio.a nexmon.c
	$(CC) -o $@ $(CFLAGS) nexmon.c $(LDFLAGS) libnexio.a

libnexio.a: libnexio.c
	$(CC) -c -I./ $(ARCH_FLAGS) libnexio.c
	$(AR) rcs libnexio.a libnexio.o

# ─── Install / Uninstall ─────────────────────────────────────────
.PHONY: all aarch64 armhf _build clean install uninstall

clean:
	rm -f libnexmonkali.so libnexio.a libnexio.o

install: libnexmonkali.so
	@echo "Installing Libnexmonkali-Plus..."
	@# Ensure directories exist
	install -d /usr/lib
	install -d /usr/bin
	@# Install library with 755 permissions
	install -m 755 libnexmonkali.so /usr/lib/
	@# Install script with 755 permissions (executable)
	install -m 755 nxsp /usr/bin/
	@# Optional: update library cache
	ldconfig || true
	@echo "--------------------------------------------------"
	@echo "SUCCESS: 'nxsp' is now installed globally."
	@echo "Usage: nxsp load | nxsp <delay> <tool>"
	@echo "--------------------------------------------------"

uninstall:
	rm -f /usr/lib/libnexmonkali.so
	rm -f /usr/bin/nxsp
	@echo "Uninstalled successfully."
