#include <windows.h>
#include <stdio.h>
#include <psapi.h>

// Dumpe des régions mémoire spécifiques où la clé RC4 pourrait être

void dump_memory_region(const char* filename, void* address, size_t size) {
    FILE* f = fopen(filename, "wb");
    if (!f) return;

    // Vérifier que la région est lisible
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE || mbi.Protect & PAGE_READONLY)) {
            fwrite(address, 1, size, f);
        }
    }

    fclose(f);
}

void dump_interesting_memory() {
    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "[*] Dumping memory regions for key search...\n");

    // Dumper le segment .data de l'exe (où les variables globales sont)
    HMODULE hMod = GetModuleHandleA(NULL);
    if (hMod) {
        MODULEINFO modInfo;
        if (GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) {
            char filename[256];

            // Dump toute l'image (code + data)
            snprintf(filename, sizeof(filename), "memory_exe.bin");
            dump_memory_region(filename, modInfo.lpBaseOfDll, modInfo.SizeOfImage);
            fprintf(log, "[+] Dumped EXE: %s (%lu bytes)\n", filename, modInfo.SizeOfImage);
        }
    }

    // Dumper quelques régions du heap
    MEMORY_BASIC_INFORMATION mbi;
    void* address = 0;
    int heap_count = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi) && heap_count < 10) {
        // Chercher les régions heap read/write
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.Protect == PAGE_READWRITE &&
            mbi.RegionSize > 10000 && mbi.RegionSize < 10000000) {

            char filename[256];
            snprintf(filename, sizeof(filename), "memory_heap_%d.bin", heap_count);
            dump_memory_region(filename, mbi.BaseAddress, mbi.RegionSize);
            fprintf(log, "[+] Dumped heap #%d: %s (%lu bytes at 0x%p)\n",
                    heap_count, filename, mbi.RegionSize, mbi.BaseAddress);
            heap_count++;
        }

        address = (char*)mbi.BaseAddress + mbi.RegionSize;
        if ((uintptr_t)address > 0x7FFFFFFF) break;
    }

    fprintf(log, "[+] Memory dump complete! Scan these files for the 40-byte RC4 key.\n");
    fclose(log);
}
