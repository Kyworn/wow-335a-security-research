#include "../include/hooks.h"
#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <math.h>

// Scanner de mémoire pour trouver la clé RC4 (40 bytes)

// Fonction définie dans hooks.c
void LogSessionKey(const unsigned char* key, size_t keylen);

// Fonction pour dumper une région mémoire spécifique
void DumpSpecificMemoryRegion(const char* filename, const unsigned char* base_address, size_t offset, size_t size, const char* description) {
    FILE* log_file = fopen(filename, "a");
    if (!log_file) return;

    unsigned char* address_to_dump = (unsigned char*)base_address + offset;
    unsigned char buffer[size];
    SIZE_T bytes_read;

    if (ReadProcessMemory(GetCurrentProcess(), address_to_dump, buffer, size, &bytes_read)) {
        fprintf(log_file, "=== Memory Dump: %s ===\n", description);
        fprintf(log_file, "Address: 0x%p\n", (void*)address_to_dump);
        fprintf(log_file, "Size: %zu bytes\n", bytes_read);
        fprintf(log_file, "Content (hex): ");
        for (size_t i = 0; i < bytes_read; i++) {
            fprintf(log_file, "%02X", buffer[i]);
        }
        fprintf(log_file, "\n\n");
    } else {
        fprintf(log_file, "!!! Failed to read memory for %s at 0x%p (Error: %lu) !!!\n", description, (void*)address_to_dump, GetLastError());
    }
    fflush(log_file);
    fclose(log_file);
}

#include <math.h>

// ... (le reste des includes)

// Pattern matching: chercher une séquence qui ressemble à une clé RC4
// La clé de session WoW est générée par SRP6 et fait 40 bytes
BOOL LooksLikeSessionKey(const unsigned char* data, size_t len) {
    if (len != 40) return FALSE;

    int zeros = 0;
    int printable_ascii = 0;
    float entropy = 0.0f;
    int counts[256] = {0};

    for (size_t i = 0; i < len; i++) {
        // 1. Compter les zéros
        if (data[i] == 0) {
            zeros++;
        }
        // 2. Compter les caractères ASCII imprimables (sauf l'espace)
        if (data[i] > 32 && data[i] < 127) {
            printable_ascii++;
        }
        // 3. Compter les occurrences de chaque octet pour l'entropie
        counts[data[i]]++;
    }

    // Règle 1: Pas trop de zéros (plus de 25% = suspect)
    if (zeros > 10) return FALSE;

    // Règle 2: Pas trop de caractères imprimables (plus de 25% = probablement du texte)
    if (printable_ascii > 10) return FALSE;

    // Règle 3: Calcul de l'entropie de Shannon
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            float p = (float)counts[i] / len;
            entropy -= p * log2f(p);
        }
    }

    // Une clé RC4 de 40 octets devrait avoir une entropie élevée.
    // L'entropie maximale pour 40 octets est log2(40) ~= 5.32.
    // Une clé aléatoire aura une entropie proche de 5.
    // Fixons un seuil raisonnable, par exemple 4.0.
    if (entropy < 4.0f) return FALSE;

    // Si toutes les règles sont passées, c'est probablement une clé.
    return TRUE;
}

// Scanner une région mémoire
void ScanMemoryRegion(const unsigned char* start, size_t size, const char* region_name) {
    static int keys_found = 0;

    for (size_t i = 0; i < size - 40; i++) {
        if (LooksLikeSessionKey(start + i, 40)) {
            keys_found++;

            FILE* keylog = fopen("session_keys.txt", "a");
            if (keylog) {
                fprintf(keylog, "=== POTENTIAL SESSION KEY #%d ===\n", keys_found);
                fprintf(keylog, "Region: %s\n", region_name);
                fprintf(keylog, "Offset: 0x%p\n", (void*)(start + i));
                fprintf(keylog, "Key (hex): ");
                for (int j = 0; j < 40; j++) {
                    fprintf(keylog, "%02X", start[i + j]);
                }
                fprintf(keylog, "\n\n");
                fflush(keylog);
                fclose(keylog);
            }

            // Log la première clé trouvée comme binaire
            if (keys_found == 1) {
                LogSessionKey(start + i, 40);
            }
        }
    }
}

// Scanner toute la mémoire du processus
void ScanProcessMemory(void) {
    FILE* log = fopen("crypto_logger.log", "a");
    if (!log) return;

    fprintf(log, "[*] Starting memory scan for RC4 session key...\n");
    fflush(log);

    HMODULE hMod = GetModuleHandleA(NULL);  // Ascension.exe
    if (!hMod) {
        fprintf(log, "[!] Failed to get module handle\n");
        fclose(log);
        return;
    }

    // Dump Battlenet::Session::Salt from Ascension.exe
    DumpSpecificMemoryRegion("memory_dumps.txt", (const unsigned char*)hMod, 0xa7eab4, 25, "Battlenet::Session::Salt");

    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
        fprintf(log, "[!] Failed to get module info\n");
        fclose(log);
        return;
    }

    fprintf(log, "[*] Scanning Ascension.exe memory...\n");
    fprintf(log, "[*] Base: 0x%p, Size: %zu bytes\n", modInfo.lpBaseOfDll, modInfo.SizeOfImage);
    fflush(log);

    // Scanner la mémoire principale de l'EXE, en ignorant les premiers 4KB (en-tête PE)
    // Le scan commence à modInfo.lpBaseOfDll + 0x1000 (4KB)
    // La taille est réduite en conséquence
    if (modInfo.SizeOfImage > 0x1000) {
        ScanMemoryRegion((const unsigned char*)modInfo.lpBaseOfDll + 0x1000, modInfo.SizeOfImage - 0x1000, "Ascension.exe (after PE header)");
    } else {
        ScanMemoryRegion((const unsigned char*)modInfo.lpBaseOfDll, modInfo.SizeOfImage, "Ascension.exe");
    }

    // Aussi scanner le heap (où les clés dynamiques sont souvent stockées)
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = 0;

    while (VirtualQuery(addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Scanner seulement les pages commit en read/write (heap)
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            char region_desc[256];
            snprintf(region_desc, sizeof(region_desc), "Heap@0x%p", mbi.BaseAddress);
            ScanMemoryRegion((const unsigned char*)mbi.BaseAddress, mbi.RegionSize, region_desc);
        }

        addr = (unsigned char*)mbi.BaseAddress + mbi.RegionSize;

        // Limiter le scan (éviter de tout scanner)
        if ((uintptr_t)addr > 0x7FFFFFFF) break;
    }

    fprintf(log, "[+] Memory scan complete\n");
    fflush(log);
    fclose(log);
}

// Hook qui se déclenche après le login (détection de "gros" paquet RECV)
// WoW envoie un paquet volumineux avec les données du personnage après login
void TriggerMemoryScanOnLogin(int packet_size) {
    static BOOL scan_done = FALSE;

    // Si on reçoit un paquet > 1KB, on est probablement in-game
    if (!scan_done && packet_size > 1024) {
        scan_done = TRUE;

        FILE* log = fopen("crypto_logger.log", "a");
        fprintf(log, "[*] Large packet detected (%d bytes), triggering memory scan\n", packet_size);
        fclose(log);

        // Scanner la mémoire
        // ScanProcessMemory();
    }
}
