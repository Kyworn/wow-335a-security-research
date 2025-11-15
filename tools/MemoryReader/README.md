# MemoryReader - Process Memory Dumping DLL

Lightweight DLL for dumping process memory regions to disk for forensic analysis.

---

## Features

- **Memory Region Enumeration:** Walks all readable memory regions
- **Selective Dumping:** Filters by protection flags and size
- **File Output:** Saves memory dumps to disk
- **Minimal Footprint:** ~50 KB compiled size

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

Output: `bin/MemoryReader.dll` (211 KB)

**SHA256:**
```
a118bd7b0ed76d8ff437859aae66e4b821b19abf5508b0abb2206efdd13c68aa
```

---

## Usage

### Method 1: dinput8 Proxy

1. Rename `MemoryReader.dll` → `dinput8.dll`
2. Place in game directory
3. Launch game

### Method 2: DLL Injection

Use your preferred DLL injector tool.

---

## Output Files

- `memory_dump_<timestamp>.bin` - Raw memory dumps
- `memory_reader_loaded.txt` - DLL initialization status
- `memory_regions.log` - Memory map information

---

## Technical Details

### Memory Enumeration

Uses Windows VirtualQuery API to walk process memory:

```c
MEMORY_BASIC_INFORMATION mbi;
VirtualQuery(address, &mbi, sizeof(mbi));
```

Filters for:
- `PAGE_READWRITE`
- `PAGE_READONLY`
- `PAGE_EXECUTE_READWRITE`

---

## Comparison with CryptoLogger

| Feature | MemoryReader | CryptoLogger |
|---------|--------------|--------------|
| Memory Dumps | ✅ Full process | ✅ Targeted regions |
| Network Hooks | ❌ | ✅ recv/send |
| Crypto Analysis | ❌ | ✅ RC4/SRP6 |
| Size | ~50 KB | ~422 KB |
| Use Case | Memory forensics | Network analysis |

**Recommendation:** Use MemoryReader for initial memory exploration, then CryptoLogger for targeted network crypto analysis.

---

## Tested On

- Windows 10 x64 (native)
- Wine 9.0 (Linux)
- WoW 3.3.5a client
- 10+ hours runtime

---

## License

MIT License - See [LICENSE](../../LICENSE)

---

## Disclaimer

For educational and authorized security research only. Not for malicious use.
