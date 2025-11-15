#!/usr/bin/env python3
"""
Scanner pour trouver la S-box RC4 (256 bytes) au lieu de la clé
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

def test_sbox_on_packet(sbox, packet_data):
    """Teste si une S-box déchiffre correctement un paquet WoW"""
    if len(packet_data) < 6:
        return False, None, None

    # Créer un cipher RC4 avec cette S-box
    rc4 = RC4([0])  # Dummy key
    rc4.S = list(sbox)  # Remplacer par la S-box trouvée
    rc4.i = 0
    rc4.j = 0

    header = rc4.crypt(packet_data[:6])

    # Parser le header
    size = struct.unpack(">H", header[:2])[0]
    opcode = struct.unpack("<I", header[2:6])[0]

    # Vérifier si ça ressemble à un paquet WoW valide
    valid_size = 0 < size < 32768
    valid_opcode = opcode < 0x1000

    return valid_size and valid_opcode, size, opcode

def is_valid_sbox(data):
    """Vérifie si 256 bytes ressemblent à une S-box RC4"""
    if len(data) != 256:
        return False

    # Une S-box RC4 doit contenir chaque valeur 0-255 exactement une fois
    values = set(data)
    return len(values) == 256 and min(data) == 0 and max(data) == 255

def scan_memory_for_sbox(memory_data, test_packets):
    """Scanne la mémoire pour trouver des S-box RC4 candidates"""
    print(f"[*] Scanning {len(memory_data)} bytes for RC4 S-boxes...")
    print(f"[*] Looking for 256-byte permutations\\n")

    candidates = []

    # Scanner par alignement de 4 bytes
    for offset in range(0, len(memory_data) - 256, 4):
        if offset % 100000 == 0:
            print(f"[*] Progress: {offset}/{len(memory_data)-256} ({offset*100//(len(memory_data)-256)}%)", end='\\r')

        sbox_candidate = memory_data[offset:offset+256]

        # Vérifier si c'est une permutation valide
        if not is_valid_sbox(sbox_candidate):
            continue

        print(f"\\n[+] Found valid S-box at offset 0x{offset:08x}, testing...")

        # Tester sur les paquets
        valid_count = 0
        results = []

        for pkt in test_packets[:10]:
            valid, size, opcode = test_sbox_on_packet(sbox_candidate, pkt)
            if valid:
                valid_count += 1
                results.append((size, opcode))

        if valid_count >= 5:
            candidates.append((offset, sbox_candidate, valid_count, results))
            print(f"[!!!] VALID S-BOX FOUND!")
            print(f"    Offset: 0x{offset:08x}")
            print(f"    Valid packets: {valid_count}/10")
            print(f"    Sample opcodes: {[hex(r[1]) for r in results[:3]]}")

    print(f"\\n[+] Scan complete!")
    return candidates

def extract_world_packets(packets_raw_file):
    """Extrait les paquets du world server depuis packets_raw.log"""
    print(f"[*] Opening {packets_raw_file}...")
    with open(packets_raw_file, 'r') as f:
        lines = f.readlines()

    print(f"[*] Read {len(lines)} lines")
    packets = []
    i = 0

    while i < len(lines):
        if i % 10000 == 0:
            print(f"    Line {i}/{len(lines)}...", end='\\r')

        line = lines[i].strip()
        if 'RECV' in line and 'bytes' in line and i > 40000:
            data_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith('['):
                data_lines.append(lines[i].strip())
                i += 1

            hex_str = ''.join(data_lines).replace(' ', '')
            if hex_str:
                try:
                    data = bytes.fromhex(hex_str)
                    if len(data) >= 6:
                        packets.append(data)
                        if len(packets) >= 50:
                            break
                except:
                    pass
        else:
            i += 1

    print(f"\\n[+] Extracted {len(packets)} packets\\n")
    return packets

# Main
if __name__ == "__main__":
    print("=" * 60)
    print("  RC4 S-Box Finder")
    print("=" * 60)
    print()

    # Extraire les paquets
    test_packets = extract_world_packets("packets_raw.log")

    if len(test_packets) == 0:
        print("[!] No packets found!")
        sys.exit(1)

    # Lire les dumps mémoire
    import glob
    memory_files = glob.glob("memory_*.bin")

    if not memory_files:
        print("[!] No memory dumps found!")
        sys.exit(1)

    print(f"[+] Found {len(memory_files)} memory dump files\\n")

    all_candidates = []
    for mem_file in memory_files:
        print(f"[*] Scanning {mem_file}...")
        try:
            with open(mem_file, 'rb') as f:
                mem_data = f.read()
            print(f"    Size: {len(mem_data)} bytes")
            candidates = scan_memory_for_sbox(mem_data, test_packets)
            all_candidates.extend(candidates)
        except Exception as e:
            print(f"    Error: {e}")

    if len(all_candidates) > 0:
        print("\\n" + "=" * 60)
        print(f"[!!!] FOUND {len(all_candidates)} S-BOX CANDIDATE(S)!")
        print("=" * 60)

        for i, (offset, sbox, valid_count, results) in enumerate(all_candidates):
            print(f"\\nCandidate #{i+1}:")
            print(f"  Offset: 0x{offset:08x}")
            print(f"  Valid decryptions: {valid_count}")
            print(f"  First 32 bytes: {sbox[:32].hex()}")
    else:
        print("\\n[!] No S-boxes found")

    print("\\n[*] Done!")
