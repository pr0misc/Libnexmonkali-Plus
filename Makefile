CC_AARCH64 = aarch64-linux-gnu-gcc
AR_AARCH64 = aarch64-linux-gnu-ar
CC_ARMHF = arm-linux-gnueabihf-gcc
AR_ARMHF = arm-linux-gnueabihf-ar

# Default to aarch64
CC = $(CC_AARCH64)
AR = $(AR_AARCH64)

CFLAGS = -std=c99 -I./
LDFLAGS = -shared -fPIC -ldl libnexio.a

# Default target
all: libnexio.a libnexmonkali.so

# Architecture-specific targets
aarch64: CC = $(CC_AARCH64)
aarch64: AR = $(AR_AARCH64)
aarch64: clean libnexio.a libnexmonkali.so
	@echo "Built for aarch64 (64-bit ARM)"

armhf: CC = $(CC_ARMHF)
armhf: AR = $(AR_ARMHF)
armhf: clean libnexio.a libnexmonkali.so
	@echo "Built for armhf (32-bit ARM)"

libnexmonkali.so: libnexio.a nexmon.c
	$(CC) -o $@ -std=c99 -I./ -I/usr/include/libnl3 nexmon.c -shared -fPIC -ldl libnexio.a

libnexio.a: libnexio.c
	$(CC) -c libnexio.c
	$(AR) rcs libnexio.a libnexio.o

.PHONY: all aarch64 armhf clean install uninstall

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
