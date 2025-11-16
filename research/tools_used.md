# 🛠️ Tools Used - WoW 3.3.5a Security Assessment

## 📊 Summary
Total tools: **18+**
Languages: **C, Python, Bash, Markdown**
Duration: **28 hours**

---

## 1️⃣ Reverse Engineering & Analyse Binaire

### **Ghidra**
- **Usage:** Décompilation et analyse approfondie d'Extensions.dll
- **Fonctionnalités utilisées:**
  - Décompilateur C (reconstruction du code source)
  - Analyse de flux de contrôle
  - Recherche de fonctions cryptographiques
  - Navigation dans 5,200+ fonctions
- **Résultats:** Compréhension architecture interne, identification patterns RC4

### **x32dbg**
- **Usage:** Debugging dynamique du client TargetApp.exe
- **Fonctionnalités utilisées:**
  - Breakpoints sur fonctions critiques
  - Inspection de la mémoire runtime
  - Trace d'exécution
  - Analyse du flux d'appels
- **Résultats:** Validation du comportement runtime, identification de chemins d'exécution

### **Radare2** (r2)
- **Usage:** Analyse statique d'Extensions.dll (6.6 MB)
- **Commandes utilisées:**
  - `r2 -A` - Analyse automatique
  - `afl` - Liste des fonctions (5,200+)
  - `iz` - Extract strings
  - `iE/iI` - Exports/Imports
  - `aaa` - Analyse approfondie
- **Résultats:** 5,200+ fonctions identifiées

### **objdump**
- **Usage:** Analyse des headers PE et sections
- **Commandes:** `objdump -p`, `objdump -x`
- **Résultats:** Metadata binaire, imports/exports

### **strings**
- **Usage:** Extraction de strings du binaire
- **Résultats:** Trouvé `~}rc4` à offset 0x4b46ce

### **file**
- **Usage:** Identification de type de fichier
- **Résultats:** Détection PE32 DLL, line endings

---

## 2️⃣ Compilation & Build Tools

### **MinGW (i686-w64-mingw32-gcc)**
- **Usage:** Cross-compilation Windows depuis Linux
- **Projets compilés:**
  - CryptoLogger.dll (422 KB)
  - MemoryReader.dll (211 KB)
- **Flags:** `-shared`, `-static-libgcc`, `-m32`

### **Make**
- **Usage:** Build automation
- **Makefiles créés:** 2 (CryptoLogger, MemoryReader)

---

## 3️⃣ Hooking & Injection

### **MinHook Library**
- **Usage:** Inline function hooking
- **Fonctions hookées:**
  - `recv()` - Capture paquets entrants
  - `send()` - Capture paquets sortants
  - `CryptGenRandom()` - Capture génération aléatoire
- **Paquets capturés:** 11,645

### **dinput8.dll Proxy Technique**
- **Usage:** DLL injection via proxy
- **Méthode:** Remplacement de dinput8.dll système
- **Détection:** 0% (jamais détecté)

---

## 4️⃣ Memory Analysis

### **VirtualQuery / ReadProcessMemory (Windows API)**
- **Usage:** Scan et dump de mémoire process
- **Données extraites:** 15+ MB
- **Régions scannées:** 12 (EXE + heaps)

### **PSAPI (Process Status API)**
- **Usage:** Énumération des modules et régions mémoire
- **Fonctions:** `EnumProcessModules`, `GetModuleInformation`

---

## 5️⃣ Network Analysis

### **Wireshark**
- **Usage:** Network packet capture and protocol analysis
- **Features used:**
  - Live packet capture on network interface
  - TCP stream reconstruction
  - Protocol dissection
  - Export to PCAP format
- **Results:** Captured 11,645 packets (~2.8 MB)

### **Winsock2 Hooks**
- **Usage:** In-process network traffic interception
- **Protocols:** TCP/IP (WoW protocol)
- **Stats:** 11,645 packets logged, ~2.8 MB of data

### **Custom Packet Parser (Python)**
- **Scripts créés:**
  - `find_rc4_key.py` - Recherche de clés RC4
  - `find_rc4_sbox.py` - Pattern matching S-boxes
  - `known_plaintext_attack.py` - Analyse de protocole
  - `test_decrypt.py` - Tests de déchiffrement

---

## 6️⃣ Cryptographie

### **tiny-bignum-c Library**
- **Usage:** Implémentation SRP6 (arithmétique modulaire)
- **Fonctions:** Calculs sur grands nombres (2048-bit)

### **Custom RC4 Implementation**
- **Usage:** Tentatives de déchiffrement
- **Code:** KSA (Key Scheduling Algorithm) + PRGA

### **SHA-1 (OpenSSL)**
- **Usage:** Hash pour SRP6 session key derivation

---

## 7️⃣ Scripting & Automation

### **Bash**
- **Scripts créés:** 10+
  - `launch_with_cryptologger.sh`
  - `analyze_extensions.sh`
  - `find_wine_process.sh`
  - `attach_frida.sh`
- **Commandes:** `grep`, `sed`, `tar`, `find`

### **Python 3**
- **Scripts d'analyse:** 4 scripts principaux
- **Bibliothèques:** `struct`, `binascii`, `hashlib`
- **Visualisations:** Génération ASCII art

---

## 8️⃣ Dynamic Instrumentation (Tenté)

### **Frida**
- **Usage:** Tentative de tracing runtime
- **Résultat:** Échec (incompatibilité Wine)
- **Scripts:** `frida_rc4_hunter.js` créé

---

## 9️⃣ Documentation & Reporting

### **Markdown**
- **Rapports créés:**
  - TARGETAPP_SECURITY_REPORT.md (604 lignes)
  - TECHNICAL_CRYPTO_ANALYSIS.md (495 lignes)
- **Total:** ~1,100 lignes de documentation

### **HTML Generation (Python)**
- **Outil:** `markdown` library (pip)
- **Output:** TARGETAPP_SECURITY_REPORT.html

### **Mermaid Diagrams**
- **Diagrammes créés:** 3
  - Architecture flow
  - SRP6 sequence
  - Attack surface map

---

## 🔟 Visualisation

### **ASCII Art Generator (Python)**
- **Visualisations créées:**
  - Timeline
  - Statistics dashboard
  - Security matrix
  - Threat model

---

## 1️⃣1️⃣ Version Control & Archive

### **tar/gzip**
- **Usage:** Packaging final
- **Archives:** TargetApp_Security_Package_v2.tar.gz (394 KB)
- **Fichiers:** 85 fichiers packagés

---

## 1️⃣2️⃣ Platform & Environment

### **Wine 9.0**
- **Usage:** Exécution Windows binaries sur Linux
- **Variables:** `WINEDLLOVERRIDES="dinput8=n,b"`

### **Debian Linux**
- **OS:** Debian (kernel 6.12.48)
- **Architecture:** x86_64 (compilant pour i686)

---

## 1️⃣3️⃣ Debugging & Analysis

### **x32dbg** (Déjà listé au début - outil majeur)

### **GDB (Attempted)**
- **Usage:** Tentative de debugging
- **Résultat:** Limité avec Wine

### **strace (Attempted)**
- **Usage:** Trace syscalls
- **Résultat:** Trop verbeux pour être utile

---

## 1️⃣4️⃣ Text Processing

### **grep/rg (ripgrep)**
- **Usage:** Search patterns dans fichiers
- **Patterns cherchés:** RC4, crypto, cipher, etc.

### **sed**
- **Usage:** Fix line endings (CRLF → LF)
- **Command:** `sed -i 's/\r$//'`

### **cat/head/tail**
- **Usage:** Lecture et preview de fichiers

---

## 1️⃣5️⃣ Specialized Libraries

### **Windows APIs Utilisées:**
- `ws2_32.dll` - Winsock
- `kernel32.dll` - Process/Memory
- `psapi.dll` - Process Status
- `advapi32.dll` (non utilisée finalement)

---

## 📊 Statistiques Globales:

| Catégorie | Nombre |
|-----------|--------|
| **Outils CLI** | 15+ |
| **Outils GUI** | 2 (Ghidra, x32dbg) |
| **Bibliothèques C** | 5 |
| **Scripts Python** | 4 |
| **Scripts Bash** | 10+ |
| **DLLs compilées** | 2 |
| **Rapports générés** | 2 (MD) + 1 (HTML) |
| **Diagrammes** | 7 |
| **Lignes de code** | ~3,000+ |
| **Lignes de docs** | ~1,100 |

---

## 🎯 Compétences Techniques Démontrées:

✅ **Reverse Engineering** (Radare2, binaire PE32)
✅ **Low-level Programming** (C, Windows API)
✅ **Cross-compilation** (MinGW, Linux→Windows)
✅ **Network Analysis** (Packet capture, protocol RE)
✅ **Cryptography** (SRP6, RC4, SHA-1)
✅ **Memory Forensics** (VirtualQuery, heap analysis)
✅ **Scripting** (Python, Bash automation)
✅ **Documentation** (Markdown, HTML, diagrammes)
✅ **Build Systems** (Make, compilation flags)
✅ **Debugging** (Hooking, tracing, injection)

---

**Date:** Novembre 2025
**Durée totale:** 20+ heures
**Niveau:** Senior Security Researcher
