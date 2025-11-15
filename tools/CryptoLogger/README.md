# CryptoLogger - Network Packet Capture DLL

Research tool for capturing and analyzing encrypted network traffic from legacy game clients.

---

## ⚠️ WARNING

This DLL hooks system-level functions and **WILL be flagged by antivirus software**. Use in isolated VM environments only for authorized security research.

---

## Features

- **recv/send Hooking:** Captures all Winsock2 network traffic
- **Memory Dumping:** Snapshots process memory at key points
- **Minimal Footprint:** ~422 KB compiled size
- **Zero Dependencies:** Statically linked for portability

---

## Building

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt install mingw-w64 make

# Arch Linux
sudo pacman -S mingw-w64-gcc make
```

### Compile

```bash
make clean
make
```

Output: `CryptoLogger.dll` (~422 KB)

---

## Usage

### Method 1: dinput8 Proxy

1. Rename `CryptoLogger.dll` → `dinput8.dll`
2. Place in game directory
3. Launch game

### Method 2: DLL Injection

Use your preferred DLL injector tool.

---

## Output Files

- `crypto_logger.log` - Hook initialization and status
- `packets_raw.log` - Captured network packets
- `session_keys.txt` - Attempted key extraction (if any)

---

## Source Structure

```
src/
├── dllmain.c         # DLL entry point
├── hooks.c           # MinHook function hooks
├── rc4.c             # RC4 implementation
├── srp6.c            # SRP6 protocol analysis
├── memory_dump.c     # Memory forensics
└── bn_ext.c          # BigNum extensions

include/
├── hooks.h
├── rc4.h
└── MinHook.h         # MinHook library

lib/
└── libMinHook.a      # MinHook static library
```

---

## Dependencies

- **MinHook:** Inline function hooking (included)
- **tiny-bignum-c:** BigNum arithmetic (included)

---

## Technical Details

### Hooked Functions

```c
ws2_32.dll!recv
ws2_32.dll!send
advapi32.dll!CryptGenRandom (optional)
```

### Hook Implementation

Uses MinHook for inline API hooking:

```c
typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
recv_t orig_recv = NULL;

int WINAPI Hook_recv(SOCKET s, char *buf, int len, int flags) {
    int result = orig_recv(s, buf, len, flags);
    if (result > 0) {
        LogPacket("RECV", buf, result);
    }
    return result;
}
```

---

## Tested On

- Windows 10 x64 (native)
- Wine 9.0 (Linux)
- WoW 3.3.5a client
- 20+ hours runtime
- Zero crashes

---

## License

MIT License - See [LICENSE](../../LICENSE)

---

## Disclaimer

For educational and authorized security research only. Not for malicious use.
