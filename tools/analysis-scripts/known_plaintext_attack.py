#!/usr/bin/env python3
"""
Known-Plaintext Attack sur les paquets WoW 3.3.5a

Si on connait le plaintext d'un paquet et qu'on a sa version chiffrée,
on peut calculer le keystream RC4: keystream = encrypted XOR plaintext

Ensuite on peut reconstruire la S-box RC4 et déchiffrer tous les paquets!
"""

import struct
import sys

def extract_packets_from_log(filename):
    """Extrait les paquets RECV du log"""
    print(f"[*] Reading {filename}...")
    with open(filename, 'r') as f:
        lines = f.readlines()

    packets = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if 'RECV' in line and 'bytes' in line:
            # Parse size
            size_str = line.split('RECV')[1].split('bytes')[0].strip()
            size = int(size_str)

            # Extract hex data
            hex_lines = []
            i += 1
            while i < len(lines) and not lines[i].startswith('['):
                hex_lines.append(lines[i].strip())
                i += 1

            hex_str = ''.join(hex_lines).replace(' ', '')
            try:
                data = bytes.fromhex(hex_str)
                packets.append(data)
            except:
                pass
        else:
            i += 1

    return packets

def find_repeating_packets(packets):
    """Trouve les paquets qui se répètent (probablement des keep-alive/ping)"""
    print(f"\n[*] Analyzing {len(packets)} packets for patterns...")

    # Group par size
    by_size = {}
    for pkt in packets:
        size = len(pkt)
        if size not in by_size:
            by_size[size] = []
        by_size[size].append(pkt)

    print(f"\n[+] Packet sizes distribution:")
    for size in sorted(by_size.keys())[:20]:
        count = len(by_size[size])
        if count > 1:
            print(f"    Size {size:4d}: {count:4d} packets")

            # Si beaucoup de paquets de même taille, checker s'ils sont identiques
            if count > 10:
                unique = set(by_size[size])
                if len(unique) < count // 2:
                    print(f"        -> Only {len(unique)} unique patterns (INTERESTING!)")
                    # Montrer les patterns
                    for idx, pattern in enumerate(list(unique)[:3]):
                        print(f"           Pattern #{idx+1}: {pattern[:16].hex()}...")

    return by_size

def attempt_known_plaintext_smsg_pong():
    """
    SMSG_PONG est la réponse à CMSG_PING
    Structure: [size:2] [opcode:4] [sequence:4]

    Si on trouve des paquets de 10 bytes qui se répètent, c'est probablement PONG
    """
    print("\n" + "="*60)
    print("  Known-Plaintext Attack: SMSG_PONG")
    print("="*60)

    # SMSG_PONG opcode = 0x01DD (WoW 3.3.5a)
    opcode = 0x01DD

    print(f"\n[*] Looking for SMSG_PONG packets...")
    print(f"    Expected format: [size:2 bytes][opcode:4 bytes = 0x{opcode:04X}][seq:4 bytes]")
    print(f"    Total size: 6 bytes encrypted header (size+opcode only)")

    # Note: En WoW, seuls les 6 premiers bytes sont chiffrés pour server->client:
    # - 2 bytes: size (big endian)
    # - 4 bytes: opcode (little endian)
    # Le reste (payload) n'est PAS chiffré!

    return None

def attempt_known_plaintext_time_sync():
    """
    SMSG_TIME_SYNC_REQ est envoyé régulièrement par le serveur
    Opcode: 0x0390
    Payload: uint32 counter

    Structure complète:
    - Header chiffré (6 bytes): [size:2][opcode:4]
    - Payload NON chiffré (4 bytes): [counter:4]
    """
    print("\n" + "="*60)
    print("  Known-Plaintext Attack: SMSG_TIME_SYNC_REQ")
    print("="*60)

    opcode = 0x0390
    print(f"\n[*] SMSG_TIME_SYNC_REQ opcode = 0x{opcode:04X}")
    print(f"    Structure: [encrypted 6 bytes header][unencrypted 4 bytes payload]")

    return None

def analyze_small_packets(by_size):
    """
    Les petits paquets sont plus faciles à attaquer
    Cherchons les paquets de 2-10 bytes
    """
    print("\n" + "="*60)
    print("  Small Packet Analysis")
    print("="*60)

    for size in range(2, 20):
        if size in by_size and len(by_size[size]) > 5:
            packets = by_size[size]
            print(f"\n[*] {len(packets)} packets of size {size}:")

            # Montrer quelques exemples
            for i, pkt in enumerate(packets[:5]):
                print(f"    #{i+1}: {pkt.hex()}")

            # Si c'est exactement 6 bytes, c'est juste un header sans payload
            if size == 6:
                print(f"\n    [!] Size 6 = header only (no payload)")
                print(f"        These are encrypted: [size:2][opcode:4]")
                print(f"        We need to guess the opcode...")

                # Essayer quelques opcodes connus
                known_opcodes = {
                    0x01DD: "SMSG_PONG",
                    0x0390: "SMSG_TIME_SYNC_REQ",
                    0x0477: "SMSG_ACCOUNT_DATA_TIMES",
                }

                print(f"\n        Trying known opcodes...")
                for pkt in packets[:3]:
                    print(f"\n        Packet: {pkt.hex()}")
                    for opc, name in known_opcodes.items():
                        # Construct expected plaintext
                        # Size = 4 (opcode size), big-endian
                        expected_size = struct.pack('>H', 4)
                        expected_opcode = struct.pack('<I', opc)
                        expected_plaintext = expected_size + expected_opcode

                        # Calculate keystream
                        keystream = bytes(a ^ b for a, b in zip(pkt, expected_plaintext))
                        print(f"          If {name} (0x{opc:04X}): keystream = {keystream.hex()}")

def main():
    print("="*60)
    print("  Known-Plaintext Attack on WoW 3.3.5a RC4")
    print("="*60)

    # Load packets
    packets = extract_packets_from_log("packets_raw.log")

    if not packets:
        print("[!] No packets found!")
        return

    print(f"\n[+] Loaded {len(packets)} packets")
    print(f"[*] First packet: {packets[0][:32].hex()}...")

    # Analyze patterns
    by_size = find_repeating_packets(packets)

    # Try different attacks
    analyze_small_packets(by_size)
    attempt_known_plaintext_smsg_pong()
    attempt_known_plaintext_time_sync()

    print("\n" + "="*60)
    print("[*] Analysis complete!")
    print("\n[*] Next steps:")
    print("    1. Identify which small packets are keep-alives")
    print("    2. Use WoW packet dumps from WowPacketParser to compare")
    print("    3. Try XOR with known opcodes to find keystream")
    print("="*60)

if __name__ == "__main__":
    main()
