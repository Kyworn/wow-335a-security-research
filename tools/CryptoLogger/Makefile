# Makefile for CryptoLogger.dll
# Cross-compilation for Windows 32-bit from Linux

CC = i686-w64-mingw32-gcc
WINDRES = i686-w64-mingw32-windres
CFLAGS = -Wall -O2 -DNDEBUG -Iinclude -Isrc/hde
LDFLAGS = -shared -static-libgcc -lws2_32 -lpsapi

# MinHook sources
MINHOOK_SRC = src/buffer.c src/hook.c src/trampoline.c src/hde/hde32.c

# Crypto sources
CRYPTO_SRC = src/rc4.c src/srp6.c src/bn.c src/bn_ext.c

# CryptoLogger sources
SRC = src/dllmain.c src/hooks.c src/memory_scanner.c src/memory_dump.c $(CRYPTO_SRC) $(MINHOOK_SRC)
OBJ = $(SRC:.c=.o)
TARGET = CryptoLogger.dll

# Installation path
INSTALL_DIR = "/home/zorko/Games/ascension-wowold/drive_c_backup_corrupted/Program Files/Ascension Launcher/resources/client"

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJ)
	@echo "[*] Linking $(TARGET)..."
	$(CC) $(LDFLAGS) -o $@ $^
	@echo "[+] Build complete: $(TARGET)"
	@ls -lh $(TARGET)

%.o: %.c
	@echo "[*] Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	@echo "[*] Cleaning build artifacts..."
	rm -f $(OBJ) $(TARGET)
	@echo "[+] Clean complete"

install: $(TARGET)
	@echo "[*] Installing to game directory..."
	cp $(TARGET) $(INSTALL_DIR)/
	@echo "[+] Installed: $(INSTALL_DIR)/$(TARGET)"

test:
	@echo "[*] Running tests..."
	@echo "[*] Checking if compiler is available..."
	@which $(CC) || (echo "ERROR: $(CC) not found. Install with: sudo apt install mingw-w64" && exit 1)
	@echo "[+] Compiler OK"
	@echo "[*] Checking if target dir exists..."
	@test -d $(INSTALL_DIR) || (echo "ERROR: Game directory not found" && exit 1)
	@echo "[+] Target directory OK"
	@echo "[*] All checks passed"

# Debug build
debug: CFLAGS += -g -DDEBUG -O0
debug: clean $(TARGET)
	@echo "[+] Debug build complete"

# Show build info
info:
	@echo "=== CryptoLogger Build Info ==="
	@echo "Compiler: $(CC)"
	@echo "Flags: $(CFLAGS)"
	@echo "Linker: $(LDFLAGS)"
	@echo "Sources: $(SRC)"
	@echo "Install: $(INSTALL_DIR)"
