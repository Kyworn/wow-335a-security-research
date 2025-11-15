# Release Notes - CryptoLogger v1.0

## ⚠️ CRITICAL WARNING

**CryptoLogger.dll is a research tool that hooks system-level functions.**

### Before Downloading:

❌ **WILL be flagged by antivirus software** (this is expected)
❌ **NOT for use on live game servers**
❌ **NOT for unauthorized access**
❌ **Educational/research purposes ONLY**

✅ **Use in isolated VM environment only**
✅ **Understand what you're doing**
✅ **Comply with all applicable laws**

---

## 📦 What's Included

### Pre-compiled Binary
- **File:** `CryptoLogger.dll`
- **Size:** ~422 KB
- **Architecture:** Windows x86 (32-bit)
- **Compiler:** MinGW GCC 11.x
- **Build:** Release (optimized)

### SHA256 Checksum
```
c2eb720aa246ccc5eaf2dd3295df9cea896a4ac9dec8f6bb9b55f4b3254e520c
```

Verify with:
```bash
sha256sum CryptoLogger.dll
```

---

## 🛠️ Functionality

CryptoLogger hooks the following Windows API functions:

1. **ws2_32.dll!recv** - Captures incoming network packets
2. **ws2_32.dll!send** - Captures outgoing network packets
3. **advapi32.dll!CryptGenRandom** - Monitors random number generation

### Logged Data:
- All network traffic (encrypted and plaintext)
- Packet timestamps
- Packet sizes and directions
- Memory dumps at key points

### Output Files Created:
- `crypto_logger.log` - Hook status and debug info
- `packets_raw.log` - Raw packet data
- `session_keys.txt` - Attempted key extraction (may be empty)
- `memory_dumps/` - Process memory snapshots

---

## 📋 Installation

### Method 1: dinput8 Proxy (Recommended)

1. Rename `CryptoLogger.dll` → `dinput8.dll`
2. Place in game client directory (same folder as .exe)
3. Launch game normally
4. DLL will be loaded automatically

### Method 2: Manual Injection

```bash
# Using dll-injector tool
dll-injector.exe --pid <game_pid> --dll CryptoLogger.dll
```

---

## 🖥️ System Requirements

- **OS:** Windows 7/8/10/11 (32-bit or 64-bit)
- **Target:** 32-bit Windows applications
- **Wine:** Compatible (tested on Wine 9.0 / Linux)
- **Permissions:** User-level (no admin required)

---

## 🧪 Testing

Tested on:
- Windows 10 x64 (native)
- Debian Linux + Wine 9.0
- WoW 3.3.5a client
- 20+ hours of runtime
- Zero crashes observed

---

## 🚨 Antivirus Detections

### Expected Behavior

CryptoLogger **WILL** be flagged by antivirus software as:
- "Generic.Trojan"
- "Suspicious.Hook"
- "PUP.Optional"
- "Hacktool"

### Why This Happens

The DLL uses techniques that are **identical to malware**:
- Function hooking (MinHook)
- Process memory access
- Network interception
- DLL injection

**These are FALSE POSITIVES** - the tool is not malicious, but uses low-level techniques that AV software flags.

### VirusTotal Results

[Will be added before release]

Expected: 40-50 / 70 engines will flag this

**This is normal for hook-based research tools.**

---

## 🔧 Building from Source

**Recommended:** Compile yourself for maximum trust.

```bash
cd tools/CryptoLogger
make clean
make

# Output: CryptoLogger.dll
```

See [tools/CryptoLogger/README.md](../tools/CryptoLogger/README.md) for details.

---

## 🐛 Troubleshooting

### DLL Not Loading

**Check:**
1. DLL is in correct directory (same as .exe)
2. Named correctly (`dinput8.dll`)
3. Antivirus didn't quarantine it

**Debug:**
- Check `dinput8_loader.log` (if using proxy)
- Run `Dependency Walker` to verify exports

### No Logs Generated

**Possible causes:**
1. Game doesn't use hooked functions (wrong target)
2. DLL loaded but hooks failed (check log)
3. Insufficient permissions (try as admin)

### Crashes

**If game crashes:**
1. Check `crypto_logger.log` for errors
2. Verify target architecture (32-bit DLL → 32-bit game)
3. Report issue with crash dump

---

## 📄 License

MIT License - See [LICENSE](../LICENSE)

**Additional Terms:**
- Educational use only
- No warranty provided
- Use at your own risk
- Author not liable for misuse

---

## 🔒 Security & Privacy

### What This Tool Does NOT Do:
- ❌ Send data over network
- ❌ Connect to external servers
- ❌ Steal credentials
- ❌ Modify game files
- ❌ Contain backdoors

### What It DOES Do:
- ✅ Hooks local functions
- ✅ Logs to local files
- ✅ Reads process memory
- ✅ Operates entirely locally

**Source code is available** - audit it yourself!

---

## 🤝 Support

### Issues & Questions
- GitHub Issues: [Open an issue](../../issues)
- Email: [Contact via GitHub Issues]

### Pull Requests
Improvements welcome! Please:
- Follow existing code style
- Add comments
- Test thoroughly

---

## 📚 Documentation

- [Main README](../README.md)
- [Research Methodology](../research/methodology.md)
- [CryptoLogger Source](../tools/CryptoLogger/README.md)

---

## ⚖️ Legal Disclaimer

By downloading and using CryptoLogger.dll, you agree to:

1. Use it only in authorized environments
2. Not use it to violate Terms of Service
3. Not use it for unauthorized access
4. Comply with all applicable laws
5. Accept all risks

**This tool is provided for research and education only.**

The author(s) are not responsible for:
- Misuse of this tool
- Damages caused by use
- Legal consequences of misuse
- Terms of Service violations

**Use responsibly and ethically.**

---

## 📊 Version History

### v1.0.0 (November 2025)
- Initial release
- MinHook-based recv/send hooking
- Memory dumping capabilities
- Tested and stable

---

## 🙏 Acknowledgments

- **MinHook** - Tsuda Kageyu (https://github.com/TsudaKageyu/minhook)
- **tiny-bignum-c** - kokke (https://github.com/kokke/tiny-bignum-c)
- **Security Research Community** - For methodologies

---

**Download at your own risk. Use ethically. Learn responsibly.**

---

*Last updated: November 2025*
