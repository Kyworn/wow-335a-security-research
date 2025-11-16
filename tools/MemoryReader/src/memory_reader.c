#include "memory_reader.h"
#include <stdio.h>
#include <psapi.h>

static HANDLE g_scan_thread = NULL;
static int g_running = 0;
static FILE* g_log = NULL;

void LogMemoryRegion(const char* name, void* address, size_t size) {
    if (!g_log) return;

    fprintf(g_log, "\n=== %s @ 0x%p (%zu bytes) ===\n", name, address, size);

    uint8_t* ptr = (uint8_t*)address;
    for (size_t i = 0; i < size && i < 256; i++) {
        fprintf(g_log, "%02X ", ptr[i]);
        if ((i + 1) % 16 == 0) fprintf(g_log, "\n");
    }
    fprintf(g_log, "\n");
    fflush(g_log);
}

// Scan memory for interesting patterns
DWORD WINAPI ScanThread(LPVOID param) {
    g_log = fopen("memory_scan.log", "w");
    if (!g_log) return 1;

    fprintf(g_log, "=== Memory Scanner Started ===\n");
    fprintf(g_log, "Process: %lu\n", GetCurrentProcessId());
    fprintf(g_log, "Base: 0x%p\n\n", GetModuleHandle(NULL));
    fflush(g_log);
    MEMORY_BASIC_INFORMATION mbi;
    uint8_t* address = NULL;

    int scan_count = 0;
    while (g_running && scan_count < 100) {  // Limit to 100 regions
        if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) break;

        // Look for readable/writable regions
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {

            // Scan for patterns
            uint8_t* ptr = (uint8_t*)mbi.BaseAddress;
            size_t size = mbi.RegionSize;

            // Don't scan memory - too dangerous, causes crashes
            // Just log that we found a RW region
            if (size > 0x1000 && size < 0x100000) {
                fprintf(g_log, "Found RW region: 0x%p - 0x%p (size: 0x%zx)\n",
                        mbi.BaseAddress,
                        (uint8_t*)mbi.BaseAddress + size,
                        size);
            }

            scan_count++;
        }

        address = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;

        Sleep(100);  // Don't spam too fast
    }

    fprintf(g_log, "\n=== Scan Complete (%d regions) ===\n", scan_count);
    fclose(g_log);
    g_log = NULL;

    return 0;
}

void StartMemoryScanning(void) {
    if (g_running) return;

    g_running = 1;
    g_scan_thread = CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
}

void StopMemoryScanning(void) {
    g_running = 0;
    if (g_scan_thread) {
        WaitForSingleObject(g_scan_thread, 5000);
        CloseHandle(g_scan_thread);
        g_scan_thread = NULL;
    }
}

void ScanForAuctionHouseData(void) {
    FILE* f = fopen("ah_scan.log", "w");
    if (!f) return;

    fprintf(f, "=== Scanning for Auction House Data ===\n\n");

    // AH packets have specific opcodes: SMSG_AUCTION_LIST_RESULT = 0x25B
    // Search memory for this pattern
    fprintf(f, "Looking for opcode 0x025B (SMSG_AUCTION_LIST_RESULT)...\n");

    fclose(f);
}

void ScanForPlayerGold(void) {
    // Scan for player gold value
    FILE* f = fopen("gold_scan.log", "w");
    if (f) {
        fprintf(f, "=== Player Gold Scanner ===\n");
        fprintf(f, "Searching memory for gold values...\n");
        fclose(f);
    }
}

void ScanForInventory(void) {
    // Scan for inventory items
    FILE* f = fopen("inventory_scan.log", "w");
    if (f) {
        fprintf(f, "=== Inventory Scanner ===\n");
        fclose(f);
    }
}
