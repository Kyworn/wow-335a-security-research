#include <windows.h>
#include <stdio.h>
#include "memory_reader.h"

// Forward declaration
static DWORD WINAPI DelayedStart(LPVOID param);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        {
            FILE* f = fopen("memory_reader_loaded.txt", "w");
            if (f) {
                fprintf(f, "MemoryReader.dll loaded successfully!\n");
                fprintf(f, "Process ID: %lu\n", GetCurrentProcessId());
                fprintf(f, "Module base: 0x%p\n", hModule);
                fclose(f);
            }

            // Start scanning after 5 seconds
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)DelayedStart, NULL, 0, NULL);
            break;
        }

        case DLL_PROCESS_DETACH:
            StopMemoryScanning();
            break;
    }
    return TRUE;
}

static DWORD WINAPI DelayedStart(LPVOID param) {
    Sleep(5000);  // Wait 5 seconds for game to initialize

    FILE* f = fopen("memory_reader_start.txt", "w");
    if (f) {
        fprintf(f, "Starting memory scanner...\n");
        fclose(f);
    }

    StartMemoryScanning();
    return 0;
}
