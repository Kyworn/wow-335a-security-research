#!/usr/bin/env python3
"""
Scanner intelligent pour trouver la clé RC4 en testant toutes les possibilités
dans les paquets capturés et les dumps mémoire.
"""

import struct
import sys

class RC4:
    def __init__(self, key):
        self.S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key[i % len(key)]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
        self.i = 0
        self.j = 0

    def crypt(self, data):
        out = bytearray()
        for byte in data:
            self.i = (self.i + 1) % 256
            self.j = (self.j + self.S[self.i]) % 256
            self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
            k = self.S[(self.S[self.i] + self.S[self.j]) % 256]
            out.append(byte ^ k)
        return bytes(out)

def test_key_on_packet(key, packet_data):
    """Teste si une clé déchiffre correctement un paquet WoW"""
    if len(packet_data) < 6:
        return False, None, None

    rc4 = RC4(key)
    header = rc4.crypt(packet_data[:6])

    # Parser le header
    size = struct.unpack(">H", header[:2])[0]
    opcode = struct.unpack("<I", header[2:6])[0]

    # Vérifier si ça ressemble à un paquet WoW valide
    valid_size = 0 < size < 32768
    valid_opcode = opcode < 0x1000

    return valid_size and valid_opcode, size, opcode

def scan_memory_for_keys(memory_data, test_packets):
    """Scanne la mémoire pour trouver des clés RC4 candidates"""
    print(f"[*] Scanning {len(memory_data)} bytes of memory...")
    print(f"[*] Testing against {len(test_packets)} packets\n")

    candidates = []

    # Optimisation: scanner seulement aligné sur 4 bytes
    step = 4
    total = (len(memory_data) - 40) // step

    for i in range(0, len(memory_data) - 40, step):
        if i % 400000 == 0:
            print(f"[*] Progress: {i}/{len(memory_data)-40} ({i*100//(len(memory_data)-40)}%)", end='\r')

        key_candidate = memory_data[i:i+40]

        # Vérification basique : pas trop de zéros
        if key_candidate.count(0) > 30:  # Max 75% de zéros
            continue

        # Tester sur seulement 3 paquets (rapide)
        valid_count = 0
        results = []

        for pkt in test_packets[:3]:
            valid, size, opcode = test_key_on_packet(key_candidate, pkt)
            if valid:
                valid_count += 1
                results.append((size, opcode))

        # Si 2/3 paquets valides, tester plus
        if valid_count >= 2:
            for pkt in test_packets[3:10]:
                valid, size, opcode = test_key_on_packet(key_candidate, pkt)
                if valid:
                    valid_count += 1
                    results.append((size, opcode))

            if valid_count >= 5:
                candidates.append((key_candidate, valid_count, results))
                print(f"\n[!] POTENTIAL KEY FOUND at offset 0x{i:08x}!")
                print(f"    Key: {key_candidate.hex()}")
                print(f"    Valid packets: {valid_count}/10")
                print(f"    Sample opcodes: {[hex(r[1]) for r in results[:3]]}")
                print()

    print(f"\n[+] Scan complete!")
    return candidates

def extract_world_packets(packets_raw_file):
    """Extrait les paquets du world server depuis packets_raw.log"""
    print(f"[*] Opening {packets_raw_file}...")
    with open(packets_raw_file, 'r') as f:
        lines = f.readlines()

    print(f"[*] Read {len(lines)} lines from log file")
    packets = []
    i = 0

    # Chercher après la liste des personnages (char enum)
    # On sait que c'est vers la ligne 40000+
    print("[*] Looking for world server packets (after line 40000)...")

    while i < len(lines):
        if i % 10000 == 0:
            print(f"    Scanning line {i}/{len(lines)}...", end='\r')

        line = lines[i].strip()
        if 'RECV' in line and 'bytes' in line and i > 40000:  # Après char enum
            # Extraire les bytes
            data_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith('['):
                data_lines.append(lines[i].strip())
                i += 1

            hex_str = ''.join(data_lines).replace(' ', '')
            if hex_str:
                try:
                    data = bytes.fromhex(hex_str)
                    if len(data) >= 6:  # Au moins un header
                        packets.append(data)
                        if len(packets) == 1:
                            print(f"\n[+] First packet found at line {i}, size: {len(data)} bytes")
                        if len(packets) >= 100:  # Suffisant
                            break
                except Exception as e:
                    pass
        else:
            i += 1

    print(f"\n[+] Extracted {len(packets)} world server packets\n")
    return packets

# Main
if __name__ == "__main__":
    print("=" * 60)
    print("  RC4 Key Finder - Brute Force Memory Scanner")
    print("=" * 60)
    print()

    # Extraire les paquets world server
    test_packets = extract_world_packets("packets_raw.log")

    if len(test_packets) == 0:
        print("[!] No world server packets found!")
        sys.exit(1)

    print(f"[*] First packet sample: {test_packets[0][:20].hex()}...")
    print()

    # Lire les dumps mémoire créés par CryptoLogger
    print("[*] Reading memory dumps...")

    import glob
    memory_files = glob.glob("memory_*.bin")

    if not memory_files:
        print("[!] No memory dumps found!")
        print("[!] Make sure you ran the game and entered the world.")
        sys.exit(1)

    print(f"[+] Found {len(memory_files)} memory dump files")

    candidates = []
    for idx, mem_file in enumerate(memory_files):
        print(f"\n[*] Scanning file {idx+1}/{len(memory_files)}: {mem_file}")
        try:
            with open(mem_file, 'rb') as f:
                mem_data = f.read()
            print(f"    Size: {len(mem_data)} bytes ({len(mem_data)//1024} KB)")
            print(f"    Testing {(len(mem_data)-40)//4} potential key positions...")
            file_candidates = scan_memory_for_keys(mem_data, test_packets)
            candidates.extend(file_candidates)
            print(f"    Found {len(file_candidates)} candidates in this file")
        except Exception as e:
            print(f"    Error: {e}")

    if len(candidates) > 0:
        print("\n" + "=" * 60)
        print(f"[!!!] FOUND {len(candidates)} KEY CANDIDATE(S)!")
        print("=" * 60)
        for i, (key, valid_count, results) in enumerate(candidates):
            print(f"\nCandidate #{i+1}:")
            print(f"  Key: {key.hex()}")
            print(f"  Valid decryptions: {valid_count}")

            # Tester plus en détail
            print(f"\n  Testing full decryption on first packet:")
            rc4 = RC4(key)
            pkt = test_packets[0]
            decrypted = rc4.crypt(pkt)
            print(f"  Decrypted: {decrypted[:40].hex()}...")
    else:
        print("\n[!] No keys found in packet data.")
        print("[!] Need to dump process memory. Run:")
        print("    sudo gcore -o ascension_dump $(pgrep -f Ascension.exe)")
        print("    Then run this script with: python3 find_rc4_key.py ascension_dump.core")

print("\n[*] Done!")
