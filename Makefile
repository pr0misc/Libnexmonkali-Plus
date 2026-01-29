CC = aarch64-linux-gnu-gcc
AR = aarch64-linux-gnu-ar

CFLAGS = -std=c99 -I./
LDFLAGS = -shared -fPIC -ldl libnexio.a

all: libnexio.a libnexmonkali.so

libnexmonkali.so: libnexio.a nexmon.c
	$(CC) -o $@ -std=c99 -I./ -I/usr/include/libnl3 nexmon.c -shared -fPIC -ldl libnexio.a

libnexio.a: libnexio.c
	$(CC) -c libnexio.c
	$(AR) rcs libnexio.a libnexio.o

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
