# Research Methodology

## Overview

This document outlines the complete methodology used in the security assessment of the World of Warcraft 3.3.5a client.

---

## Phase 1: Reconnaissance (2 hours)

### Objectives
- Understand the target application architecture
- Identify key binaries and their relationships
- Gather initial metadata

### Tools Used
- `file` - Binary type identification
- `strings` - String extraction
- `objdump` - PE header analysis

### Key Findings
- Main executable: GameClient.exe
- Extension library: Extensions.dll (6.6 MB, 5,200+ functions)
- Architecture: PE32 (i386)
- No code signing detected

---

## Phase 2: Static Binary Analysis (6 hours)

### Objectives
- Reverse engineer Extensions.dll
- Map function call graphs
- Identify cryptographic functions

### Tools Used
- **Ghidra** - Primary decompilation tool
- **Radare2** - Command-line analysis
- **x32dbg** - Debug symbol analysis

### Process
1. Load Extensions.dll into Ghidra
2. Auto-analysis (30 minutes processing time)
3. Manual function identification
4. Search for crypto patterns (RC4, SRP6)
5. Document architecture

### Key Findings
- 5,200+ functions identified
- Custom RC4 implementation (no Windows Crypto API)
- String `~}rc4` found at offset 0x4b46ce
- No anti-tamper protection detected

---

## Phase 3: DLL Injection (2 hours)

### Objectives
- Achieve code injection without detection
- Hook network functions
- Capture encrypted traffic

### Technique: dinput8.dll Proxy

**Why this works:**
- Games often load dinput8.dll for input handling
- Can be replaced with proxy DLL
- Proxy loads real DLL + custom code

### Implementation
```c
// dinput8_proxy.c
HMODULE LoadOriginalDLL() {
    return LoadLibrary("C:\\Windows\\System32\\dinput8.dll");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        LoadLibrary("CryptoLogger.dll");  // Load our hook DLL
    }
    return TRUE;
}
```

### Result
✅ Successfully injected
✅ 0% detection rate across 20+ hours

---

## Phase 4: Network Hooking (4 hours)

### Objectives
- Intercept all network traffic
- Capture packets in real-time
- Analyze protocol structure

### Technique: MinHook Inline Hooking

**Functions hooked:**
- `ws2_32.dll!recv` - Incoming packets
- `ws2_32.dll!send` - Outgoing packets

### Implementation
```c
#include "MinHook.h"

typedef int (WINAPI *recv_t)(SOCKET, char*, int, int);
recv_t orig_recv = NULL;

int WINAPI Hook_recv(SOCKET s, char *buf, int len, int flags) {
    int result = orig_recv(s, buf, len, flags);
    if (result > 0) {
        LogPacket("RECV", buf, result);
    }
    return result;
}

void InitHooks() {
    MH_Initialize();
    MH_CreateHook(&recv, &Hook_recv, (void**)&orig_recv);
    MH_EnableHook(MH_ALL_HOOKS);
}
```

### Results
- 11,645 packets captured
- ~2.8 MB of network data
- 369 unique opcodes identified

---

## Phase 5: Protocol Analysis (3 hours)

### Objectives
- Understand packet structure
- Identify authentication flow
- Document protocol opcodes

### Packet Structure Discovered

**Client → Server (CMSG):**
```
[2 bytes: size] [4 bytes: opcode] [variable: payload]
```

**Server → Client (SMSG):**
```
[2 bytes: size] [2 bytes: opcode] [variable: payload]
```

### Authentication Flow (SRP6)

```
1. Client sends username + public key A
2. Server responds with public key B + salt
3. Both compute shared secret S
4. SessionKey = SHA1(S)[0:40]
5. Initialize RC4 with SessionKey
```

---

## Phase 6: Cryptographic Analysis (5 hours)

### Objectives
- Understand encryption implementation
- Attempt key extraction
- Validate security

### Techniques Attempted

#### 1. Memory Scanning
- Scanned for 40-byte keys
- Scanned for 256-byte S-boxes
- Result: ❌ Found candidates but none worked

#### 2. Known-Plaintext Attack
- Attempted to derive keystream
- Result: ❌ No reliable known-plaintext pairs

#### 3. CryptGenRandom Hooking
- Hooked Windows RNG
- Result: ❌ Not used for SRP6 'a' value

#### 4. S-box Pattern Matching
- Found 100+ valid RC4 S-boxes
- Result: ❌ Timing mismatch (state evolved)

### Conclusion
✅ **Cryptography is SECURE**
- Unable to extract keys despite extensive attempts
- Proper key management
- No obvious implementation flaws

---

## Phase 7: Memory Forensics (2 hours)

### Objectives
- Dump process memory
- Analyze heap structures
- Search for sensitive data

### Tools
- VirtualQuery
- ReadProcessMemory
- Custom memory scanner

### Results
- 15+ MB memory dumped
- 12 regions scanned (EXE + heaps)
- No plaintext keys found

---

## Phase 8: Documentation (3 hours)

### Deliverables Created
1. Main Security Report (19 pages)
2. Technical Cryptographic Analysis (495 lines)
3. Visual diagrams (7 diagrams)
4. Tool documentation
5. Methodology (this document)

---

## Phase 9: Responsible Disclosure (1 hour)

### Process
1. Prepared complete package
2. Contacted software maintainers via Discord
3. Professional disclosure message sent
4. Received acknowledgment
5. Discussed findings with technical team

### Outcome
Team acknowledged receipt but declined to act on client-side findings.

---

## Total Time Investment

| Phase | Hours |
|-------|-------|
| Reconnaissance | 2 |
| Static Analysis | 6 |
| DLL Injection | 2 |
| Network Hooking | 4 |
| Protocol Analysis | 3 |
| Crypto Analysis | 5 |
| Memory Forensics | 2 |
| Documentation | 3 |
| Disclosure | 1 |
| **TOTAL** | **28 hours** |

---

## Lessons Learned

### Technical
- Legacy game clients have minimal protection
- Custom crypto implementations can be secure
- DLL injection via proxy is trivial
- Memory forensics has limitations with evolving state

### Professional
- Responsible disclosure doesn't always lead to action
- Documentation is as important as findings
- Clear communication of risk vs reality is crucial

### Tools
- Ghidra is excellent for large binaries
- x32dbg complements static analysis well
- MinHook is reliable for function hooking
- Python is great for quick analysis scripts

---

## Future Work

Potential areas for deeper research:

1. **Server-side validation testing**
   - Requires authorized test environment
   - Would demonstrate actual exploitability

2. **Deeper Extensions.dll analysis**
   - Complete function mapping
   - Control flow analysis
   - Vulnerability hunting

3. **Memory manipulation POC**
   - Direct memory modification
   - Game state tampering
   - Impact assessment

---

*This methodology can serve as a template for similar game client assessments.*
