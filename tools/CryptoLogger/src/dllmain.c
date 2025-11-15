#include <windows.h>
#include <stdio.h>
#include "../include/hooks.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);

            FILE* log = fopen("crypto_logger.log", "w");
            fprintf(log, "[*] CryptoLogger.dll loaded\n");
            fprintf(log, "[*] PID: %lu\n", GetCurrentProcessId());
            fprintf(log, "[*] Base address: 0x%p\n", hModule);
            fclose(log);
            break;

        case DLL_PROCESS_DETACH:
            CleanupHooks();
            break;
    }
    return TRUE;
}

// Fonction export\u00e9e appel\u00e9e par dinput8.dll
__declspec(dllexport) void InitCryptoHooks(void) {
    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "\n[*] InitCryptoHooks() called\n");

    if (!InitHooks()) {
        fprintf(log, "[!] Failed to initialize hooks\n");
        fclose(log);
        return;
    }

    fprintf(log, "[+] All hooks initialized successfully!\n");
    fprintf(log, "[*] Monitoring network traffic...\n");
    fclose(log);
}
