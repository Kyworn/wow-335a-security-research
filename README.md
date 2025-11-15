# World of Warcraft 3.3.5a Client Security Research

> Educational security assessment of a legacy MMO game client

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![Research](https://img.shields.io/badge/type-Security%20Research-red)

## ⚠️ CRITICAL DISCLAIMER

**This research was conducted for EDUCATIONAL PURPOSES ONLY.**

All testing was performed on a **personal test environment** with no impact on live systems or other users. Findings were **responsibly disclosed** to the affected party before public release.

### DO NOT:
- ❌ Use these tools for unauthorized access
- ❌ Attack live game servers
- ❌ Violate Terms of Service
- ❌ Engage in malicious activities
- ❌ Distribute game client binaries

### DO:
- ✅ Learn reverse engineering techniques
- ✅ Study security assessment methodology
- ✅ Use in authorized research environments
- ✅ Conduct responsible security research

**This project is for security researchers, students, and educators ONLY.**

---

## 📊 Project Overview

Comprehensive security assessment of a World of Warcraft 3.3.5a-based private server game client, documenting the complete methodology from static analysis to cryptographic evaluation.

### Research Stats:
- **Duration:** 20+ hours of analysis
- **Binary Size:** 6.6 MB game extension DLL analyzed
- **Functions Reverse Engineered:** 5,200+
- **Network Packets Captured:** 11,645
- **Protocols Analyzed:** SRP6 authentication + RC4 encryption
- **Tools Used:** 17+ (Ghidra, Radare2, x32dbg, MinGW, Python, etc.)

---

## 🎯 Key Findings

### ✅ Positive Security Findings

**Cryptographic Implementation: SECURE**

- **SRP6 Authentication:** Properly implemented zero-knowledge proof protocol
- **RC4 Encryption:** 40-byte (320-bit) session keys with separate send/recv contexts
- **Key Derivation:** Secure session key generation from SRP6 shared secret
- **No Exploitable Crypto Flaws:** Unable to extract session keys despite extensive attempts

**Assessment:** The networking layer cryptography is **well-implemented and secure**.

### ⚠️ Areas of Concern

**Client-Side Integrity: ABSENT**

- **No Anti-Cheat Protection:** 0% detection rate across 20+ hours of testing
- **DLL Injection:** Trivially possible via dinput8 proxy technique
- **Memory Manipulation:** Feasible without detection
- **Function Hooking:** Successfully hooked recv/send with MinHook

**Note:** While these are expected properties of legacy client-side binaries, they represent potential attack vectors for malicious actors.

---

## 🛠️ Tools & Technologies Used

### Reverse Engineering
- **Ghidra** - Decompilation and deep analysis
- **x32dbg** - Dynamic debugging
- **Radare2** - Static binary analysis
- **objdump/strings** - Binary inspection

### Development
- **MinGW** - Cross-compilation (Linux → Windows)
- **MinHook** - Inline function hooking library
- **C Programming** - Low-level systems programming
- **Python 3** - Analysis scripts and automation

### Analysis
- **Network Protocol Analysis** - Custom packet parser
- **Memory Forensics** - VirtualQuery, ReadProcessMemory
- **Cryptographic Analysis** - SRP6 + RC4 implementation review

See [research/tools_used.md](./research/tools_used.md) for complete list.

---

## 📁 Repository Structure

```
wow-335a-security-research/
├── README.md                    # This file
├── LICENSE                      # MIT License with research addendum
├── .gitignore
│
├── docs/
│   ├── SECURITY_REPORT.md      # Main security assessment report
│   ├── TECHNICAL_ANALYSIS.md   # Deep-dive cryptographic analysis
│   └── diagrams/                # Architecture & flow diagrams
│
├── tools/
│   ├── CryptoLogger/           # Network packet capture DLL
│   │   ├── src/                # Source code (C)
│   │   ├── include/            # Headers
│   │   ├── Makefile            # Build system
│   │   └── README.md
│   │
│   └── analysis-scripts/       # Python analysis tools
│       ├── find_rc4_key.py
│       ├── find_rc4_sbox.py
│       └── packet_parser.py
│
├── research/
│   ├── methodology.md          # Research methodology
│   ├── tools_used.md           # Complete toolchain documentation
│   └── lessons_learned.md      # Key takeaways
│
└── samples/
    └── sanitized_packets.txt   # Anonymized packet samples
```

---

## 🔧 Building CryptoLogger

### Prerequisites
```bash
# Debian/Ubuntu
sudo apt install mingw-w64 make

# Arch Linux
sudo pacman -S mingw-w64-gcc make
```

### Compilation
```bash
cd tools/CryptoLogger
make clean
make
```

Output: `CryptoLogger.dll` (source-compiled version)

### ⚠️ Pre-compiled Binary

A pre-compiled binary is available in [GitHub Releases](../../releases).

**WARNING:** This DLL hooks system functions and **WILL be flagged by antivirus software**. This is expected behavior for hook-based research tools. Use in **isolated VM environment ONLY**.

**SHA256:** [Will be provided in release]

---

## 📖 Documentation

### Main Reports
- **[Security Report](./docs/SECURITY_REPORT.md)** - Complete vulnerability assessment
- **[Technical Analysis](./docs/TECHNICAL_ANALYSIS.md)** - Cryptographic deep-dive

### Research Documentation
- **[Methodology](./research/methodology.md)** - Step-by-step research process
- **[Tools Used](./research/tools_used.md)** - Complete toolchain (17+ tools)
- **[Lessons Learned](./research/lessons_learned.md)** - Key insights

### Architecture Diagrams
- [Architecture Flow](./docs/diagrams/architecture_flow.mmd) - System architecture
- [SRP6 Sequence](./docs/diagrams/srp6_sequence.mmd) - Authentication flow
- [Attack Surface](./docs/diagrams/attack_surface.mmd) - Threat model

---

## 🎓 Educational Value

This project demonstrates practical skills in:

### Technical Skills
- ✅ Binary reverse engineering (PE32 format)
- ✅ Network protocol analysis
- ✅ Cryptographic implementation review
- ✅ Memory forensics and process analysis
- ✅ DLL injection and function hooking
- ✅ Cross-platform development (Linux → Windows)

### Professional Skills
- ✅ Security assessment methodology
- ✅ Professional technical reporting
- ✅ Responsible disclosure practices
- ✅ Documentation and communication

---

## 📚 Research Methodology

1. **Static Binary Analysis**
   - Ghidra decompilation of 6.6 MB game extension
   - Function identification and mapping (5,200+ functions)
   - String and metadata extraction

2. **Dynamic Instrumentation**
   - DLL injection via dinput8 proxy technique
   - MinHook-based recv/send interception
   - Real-time packet capture (11,645 packets)

3. **Network Protocol Analysis**
   - Packet structure reverse engineering
   - Protocol state machine mapping
   - Opcode identification (369 unique)

4. **Cryptographic Analysis**
   - SRP6 authentication flow validation
   - RC4 implementation review
   - Session key derivation analysis
   - Attempted key extraction (unsuccessful - good sign!)

5. **Responsible Disclosure**
   - Private disclosure to affected party
   - 90-day embargo period observed
   - Professional vulnerability reporting

---

## 🤝 Responsible Disclosure Timeline

- **Day 0:** Research commenced
- **Day 7:** Initial findings documented
- **Day 14:** Complete assessment finished
- **Day 15:** Private disclosure to software maintainers
- **Day 16:** Acknowledgment received
- **Day 90:** Public release (this repository)

All findings were disclosed privately before public release.

---

## ⚖️ Legal & Ethical Considerations

This research was conducted in compliance with:

- ✅ **Responsible Disclosure Guidelines** - CERT/CC standards
- ✅ **Educational Fair Use** - Research and educational purposes
- ✅ **No Unauthorized Access** - Personal test environment only
- ✅ **No Third-Party Impact** - Zero effect on other users
- ✅ **No Circumvention** - Analysis only, no active exploitation

### Legal Notice

The game client binary analyzed is proprietary software and is **NOT included** in this repository. Only research findings, methodology, and self-developed tools are provided.

No game assets, binaries, or proprietary code are redistributed.

---

## 🌟 Acknowledgments

- **Ghidra** - NSA's open-source reverse engineering tool
- **Radare2** - UNIX-like reverse engineering framework
- **MinHook** - Minimalistic x86/x64 API hooking library
- **Security Research Community** - For methodologies and best practices

---

## 📧 Contact

For questions about this research or responsible disclosure inquiries:

- **GitHub Issues:** [Open an issue](../../issues)
- **Twitter/X:** [@Zorko] (optional)

---

## 📄 Citation

If you use this research in academic work, please cite:

```
@misc{wow335a_security_research,
  author = {Zorko},
  title = {World of Warcraft 3.3.5a Client Security Research},
  year = {2025},
  publisher = {GitHub},
  url = {https://github.com/Kyworn/wow-335a-security-research}
}
```

---

## 🔒 Security

If you discover security issues in the tools provided in this repository, please report them responsibly via GitHub Security Advisories or private email.

---

**Use responsibly. Learn ethically. Secure safely.**

---

*Last updated: November 2025*
