#include "../include/hooks.h"
#include "../include/MinHook.h"
#include "rc4.h"
#include "srp6.h"
#include "memory_dump.h"
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>
#include <time.h>
#include <psapi.h>
#include <string.h>

rc4_ctx g_send_ctx;
rc4_ctx g_recv_ctx;
int g_rc4_initialized = 0;
uint8_t g_client_public_key[32];  // Client's A value from CMSG_AUTH_SESSION
int g_client_key_captured = 0;

// Using MinHook for inline hooking
// ... (le reste du fichier jusqu'à Hook_recv)

// Original function pointers
typedef int (WINAPI *recv_t)(SOCKET s, char *buf, int len, int flags);
typedef int (WINAPI *send_t)(SOCKET s, const char *buf, int len, int flags);
typedef BOOL (WINAPI *CryptGenRandom_t)(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

static recv_t orig_recv = NULL;
static send_t orig_send = NULL;
static CryptGenRandom_t orig_CryptGenRandom = NULL;

// Log files
static FILE* g_keylog = NULL;
static FILE* g_packetlog = NULL;
static FILE* g_ahlog = NULL;

// Statistics
static uint32_t g_packets_recv = 0;
static uint32_t g_packets_send = 0;

void InitLogs(void) {
    if (!g_keylog) {
        g_keylog = fopen("session_keys.txt", "w");
        if (g_keylog) {
            fprintf(g_keylog, "=== CryptoLogger Session Keys ===\n");
            fprintf(g_keylog, "Started: %ld\n\n", time(NULL));
            fflush(g_keylog);
        }
    }

    if (!g_packetlog) {
        g_packetlog = fopen("packets_raw.log", "wb");
    }

    if (!g_ahlog) {
        g_ahlog = fopen("ah_packets.csv", "w");
        if (g_ahlog) {
            fprintf(g_ahlog, "timestamp,direction,size,opcode_hex,data_hex\n");
            fflush(g_ahlog);
        }
    }
}

void LogDecryptedPacket(const char* type, const unsigned char* data, int len) {
    FILE* f = fopen("decrypted_packets.txt", "a");
    if (!f) return;
    fprintf(f, "=== %s Packet (size: %d) ===\n", type, len);
    for (int i = 0; i < len; i++) {
        fprintf(f, "%02X", data[i]);
    }
    fprintf(f, "\n\n");
    fclose(f);
}

void LogRawPacket(const char* direction, const unsigned char* buf, int len) {
    if (!g_packetlog) return;

    time_t now = time(NULL);
    fprintf(g_packetlog, "[%ld] %s %d bytes\n", now, direction, len);

    for (int i = 0; i < len; i++) {
        fprintf(g_packetlog, "%02X ", buf[i]);
        if ((i + 1) % 16 == 0) fprintf(g_packetlog, "\n");
    }
    fprintf(g_packetlog, "\n\n");
    fflush(g_packetlog);

    // Dump first 256 bytes to a separate file for analysis
    FILE* dump_file = fopen("packet_dumps.txt", "a");
    if (dump_file) {
        fprintf(dump_file, "=== %s Packet (size: %d) ===\n", direction, len);
        int dump_len = (len > 256) ? 256 : len;
        for (int i = 0; i < dump_len; i++) {
            fprintf(dump_file, "%02X", buf[i]);
        }
        fprintf(dump_file, "\n\n");
        fclose(dump_file);
    }
}

void LogSessionKey(const unsigned char* key, size_t keylen) {
    if (!g_keylog) InitLogs();
    if (!g_keylog) return;

    fprintf(g_keylog, "=== SESSION KEY CAPTURED ===\n");
    fprintf(g_keylog, "Timestamp: %ld\n", time(NULL));
    fprintf(g_keylog, "Key Length: %zu bytes\n", keylen);
    fprintf(g_keylog, "Key (hex): ");
    for (size_t i = 0; i < keylen; i++) {
        fprintf(g_keylog, "%02X", key[i]);
    }
    fprintf(g_keylog, "\n\n");
    fflush(g_keylog);

    // Save binary format for bot
    FILE* keybin = fopen("session_key.bin", "wb");
    if (keybin) {
        fwrite(&keylen, sizeof(size_t), 1, keybin);
        fwrite(key, 1, keylen, keybin);
        fclose(keybin);
    }

    // Save timestamp
    FILE* keytime = fopen("session_key.time", "w");
    if (keytime) {
        fprintf(keytime, "%ld\n", time(NULL));
        fclose(keytime);
    }
}

// Hook recv
int WINAPI Hook_recv(SOCKET s, char *buf, int len, int flags) {
    int result = orig_recv(s, buf, len, flags);

    if (result > 0) {
        g_packets_recv++;
        LogRawPacket("RECV", (unsigned char*)buf, result);

        // Check for SMSG_AUTH_CHALLENGE (opcode 0x02E6)
        if (!g_rc4_initialized && result > 66 && *(uint16_t*)buf == 0x02E6) {
            FILE* log = fopen("crypto_logger.log", "a");
            fprintf(log, "[!!!] SMSG_AUTH_CHALLENGE detected! Calculating dynamic session key.\n");

            const uint8_t* salt = (const uint8_t*)buf + 4;
            const uint8_t* server_b = (const uint8_t*)buf + 36;
            
            uint8_t session_key[40];
            srp6_calculate_session_key(
                "info@zorko.xyz",
                "YsNi4FMFt3yGz5sA",
                salt,
                server_b,
                g_client_public_key,  // Use captured client public key
                session_key
            );

            fprintf(log, "[!!!] Dynamic key calculated. Initializing RC4 ciphers.\n");
            
            // Log the key for debugging
            fprintf(log, "Key: ");
            for(int i=0; i<40; ++i) fprintf(log, "%02X", session_key[i]);
            fprintf(log, "\n");
            fclose(log);

            rc4_init(&g_send_ctx, session_key, sizeof(session_key));
            rc4_init(&g_recv_ctx, session_key, sizeof(session_key));
            g_rc4_initialized = 1;

            // Dumper la mémoire pour scanner la vraie clé RC4
            dump_interesting_memory();
        }
        else if (g_rc4_initialized) {
            unsigned char* decrypted_buf = (unsigned char*)malloc(result);
            if (decrypted_buf) {
                rc4_crypt(&g_recv_ctx, (unsigned char*)buf, decrypted_buf, result);
                LogDecryptedPacket("RECV (DECRYPTED)", decrypted_buf, result);
                free(decrypted_buf);
            }
        }
    }

    return result;
}

// Helper function to find a substring in a memory block
const char* find_substr(const char* haystack, size_t haystack_len, const char* needle, size_t needle_len) {
    if (needle_len == 0) return haystack;
    if (haystack_len < needle_len) return NULL;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

// Thread function to run the memory scan
DWORD WINAPI ScanThread(LPVOID lpParam) {
    ScanProcessMemory();
    return 0;
}

// Hook send
int WINAPI Hook_send(SOCKET s, const char *buf, int len, int flags) {
    if (len > 0) {
        g_packets_send++;
        LogRawPacket("SEND", (unsigned char*)buf, len);

        // Check for CMSG_AUTH_SESSION packet (contains email)
        if (!g_client_key_captured && find_substr(buf, len, "info@zorko.xyz", 15) != NULL) {
            FILE* log = fopen("crypto_logger.log", "a");
            fprintf(log, "[!!!] CMSG_AUTH_SESSION detected! Extracting client public key A...\n");

            // CMSG_AUTH_SESSION structure (WoW 3.3.5a):
            // uint32 build
            // uint32 loginServerID
            // string account (null-terminated)
            // uint32 loginServerType
            // [... more fields ...]
            // uint8[20] clientProof  <- This contains part of the crypto
            // [... addon data ...]

            // Actually, client public key A is sent earlier, we need to find it differently
            // For now, let's extract it from the right offset in AUTH_SESSION
            // The structure is complex, let's dump the whole packet

            fprintf(log, "CMSG_AUTH_SESSION packet (%d bytes), looking for A...\n", len);

            // Try to find A - it's 32 bytes and should be after the username
            const char* username_pos = find_substr(buf, len, "info@zorko.xyz", 15);
            if (username_pos) {
                // Skip past username + null terminator + some fields
                const uint8_t* pos = (const uint8_t*)(username_pos + 15 + 1);
                int remaining = len - (pos - (uint8_t*)buf);

                if (remaining >= 32) {
                    // Try different offsets to find A
                    // Usually it's around 40-60 bytes after username
                    int offset_to_try[] = {0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40};
                    for (int i = 0; i < sizeof(offset_to_try)/sizeof(int); i++) {
                        if (remaining >= offset_to_try[i] + 32) {
                            memcpy(g_client_public_key, pos + offset_to_try[i], 32);
                            fprintf(log, "Captured potential A at offset +%d: ", offset_to_try[i]);
                            for(int j=0; j<32; j++) fprintf(log, "%02X", g_client_public_key[j]);
                            fprintf(log, "\n");
                            break;  // Take first attempt for now
                        }
                    }
                    g_client_key_captured = 1;
                }
            }

            fclose(log);
            CreateThread(NULL, 0, ScanThread, NULL, 0, NULL);
        }

        if (g_rc4_initialized) {
            // The game already encrypts the buffer, we are just logging the plaintext equivalent
            // by decrypting it with our own cipher state.
            unsigned char* decrypted_buf = (unsigned char*)malloc(len);
            if (decrypted_buf) {
                // To "decrypt" what the client is sending, we use the send context.
                rc4_crypt(&g_send_ctx, (unsigned char*)buf, decrypted_buf, len);
                LogDecryptedPacket("SEND (DECRYPTED)", decrypted_buf, len);
                free(decrypted_buf);
            }
        }
    }

    return orig_send(s, buf, len, flags);
}

// Simple IAT hook (fallback if MinHook not available)
BOOL HookIAT(LPCSTR moduleName, LPCSTR funcName, void* hookFunc, void** origFunc) {
    HMODULE hMod = GetModuleHandleA(NULL);  // Ascension.exe
    if (!hMod) return FALSE;

    // Get DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    // Get NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // Get import directory
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hMod +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Iterate through import descriptors
    for (; importDesc->Name; importDesc++) {
        LPCSTR dllName = (LPCSTR)((BYTE*)hMod + importDesc->Name);

        if (_stricmp(dllName, moduleName) != 0) continue;

        // Found the right DLL, now find the function
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->FirstThunk);
        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + importDesc->OriginalFirstThunk);

        for (; thunk->u1.Function; thunk++, origThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(origThunk->u1.Ordinal)) continue;

            PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hMod + origThunk->u1.AddressOfData);
            if (strcmp((char*)import->Name, funcName) != 0) continue;

            // Found it! Save original and replace
            DWORD oldProtect;
            VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect);

            if (origFunc) *origFunc = (void*)thunk->u1.Function;
            thunk->u1.Function = (DWORD_PTR)hookFunc;

            VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &oldProtect);

            return TRUE;
        }
    }

    return FALSE;
}

BOOL HookRecv(void) {
    FILE* log = fopen("crypto_logger.log", "a");

    // Try MinHook first
    if (MH_CreateHookApi(L"ws2_32", "recv", &Hook_recv, (LPVOID*)&orig_recv) == MH_OK) {
        if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
            fprintf(log, "[+] recv hooked via MinHook (orig: 0x%p)\n", orig_recv);
            fclose(log);
            return TRUE;
        }
    }

    // Fallback to IAT hooking
    if (HookIAT("WS2_32.dll", "recv", Hook_recv, (void**)&orig_recv)) {
        fprintf(log, "[+] recv hooked via IAT (orig: 0x%p)\n", orig_recv);
        fclose(log);
        return TRUE;
    }

    fprintf(log, "[!] Failed to hook recv\n");
    fclose(log);
    return FALSE;
}

BOOL HookSend(void) {
    FILE* log = fopen("crypto_logger.log", "a");

    // Try MinHook first
    if (MH_CreateHookApi(L"ws2_32", "send", &Hook_send, (LPVOID*)&orig_send) == MH_OK) {
        if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
            fprintf(log, "[+] send hooked via MinHook (orig: 0x%p)\n", orig_send);
            fclose(log);
            return TRUE;
        }
    }

    // Fallback to IAT hooking
    if (HookIAT("WS2_32.dll", "send", Hook_send, (void**)&orig_send)) {
        fprintf(log, "[+] send hooked via IAT (orig: 0x%p)\n", orig_send);
        fclose(log);
        return TRUE;
    }

    fprintf(log, "[!] Failed to hook send\n");
    fclose(log);
    return FALSE;
}

// Hook CryptGenRandom
BOOL WINAPI Hook_CryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {
    // Call original first
    BOOL result = orig_CryptGenRandom(hProv, dwLen, pbBuffer);

    if (result && dwLen > 0) {
        FILE* log = fopen("crypto_random.log", "a");
        if (log) {
            fprintf(log, "[*] CryptGenRandom called: %lu bytes\n", dwLen);
            fprintf(log, "    Data: ");
            for (DWORD i = 0; i < dwLen && i < 128; i++) {
                fprintf(log, "%02X", pbBuffer[i]);
            }
            fprintf(log, "\n");
            fflush(log);
            fclose(log);
        }

        // If it's 19 or 32 bytes, might be SRP6 'a' value!
        if (dwLen == 19 || dwLen == 32) {
            FILE* srp_log = fopen("srp6_randoms.log", "a");
            if (srp_log) {
                fprintf(srp_log, "[!!!] SRP6 candidate (%lu bytes): ", dwLen);
                for (DWORD i = 0; i < dwLen; i++) {
                    fprintf(srp_log, "%02X", pbBuffer[i]);
                }
                fprintf(srp_log, "\n");
                fflush(srp_log);
                fclose(srp_log);
            }
        }
    }

    return result;
}

BOOL HookCryptGenRandom(void) {
    FILE* log = fopen("crypto_logger.log", "a");

    // Hook CryptGenRandom from ADVAPI32.dll
    if (MH_CreateHookApi(L"advapi32", "CryptGenRandom", &Hook_CryptGenRandom, (LPVOID*)&orig_CryptGenRandom) == MH_OK) {
        if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK) {
            fprintf(log, "[+] CryptGenRandom hooked via MinHook (orig: 0x%p)\n", orig_CryptGenRandom);
            fclose(log);
            return TRUE;
        }
    }

    fprintf(log, "[!] Failed to hook CryptGenRandom\n");
    fclose(log);
    return FALSE;
}

BOOL HookRC4Init(void* address) {
    // TODO: Implement with MinHook once address is found
    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "[*] RC4::Init hook requested at 0x%p (not implemented yet)\n", address);
    fclose(log);
    return FALSE;
}

BOOL HookRC4Process(void* address) {
    // TODO: Implement with MinHook once address is found
    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "[*] RC4::ProcessData hook requested at 0x%p (not implemented yet)\n", address);
    fclose(log);
    return FALSE;
}

BOOL InitHooks(void) {
    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "[*] Initializing hooks...\n");

    // Initialize MinHook
    if (MH_Initialize() != MH_OK) {
        fprintf(log, "[!] MinHook initialization failed\n");
        fclose(log);
        return FALSE;
    }
    fprintf(log, "[+] MinHook initialized\n");

    InitLogs();

    BOOL success = TRUE;

    if (!HookRecv()) {
        fprintf(log, "[!] Failed to hook recv\n");
        success = FALSE;
    }

    if (!HookSend()) {
        fprintf(log, "[!] Failed to hook send\n");
        success = FALSE;
    }

    if (!HookCryptGenRandom()) {
        fprintf(log, "[!] Failed to hook CryptGenRandom\n");
        // Don't fail - this is optional
    }

    fprintf(log, "[*] Network hooks: %s\n", success ? "OK" : "PARTIAL");
    fclose(log);

    return success;
}

void CleanupHooks(void) {
    if (g_keylog) {
        fprintf(g_keylog, "\n=== Session ended ===\n");
        fprintf(g_keylog, "Total packets: RECV=%u, SEND=%u\n", g_packets_recv, g_packets_send);
        fclose(g_keylog);
        g_keylog = NULL;
    }

    if (g_packetlog) {
        fclose(g_packetlog);
        g_packetlog = NULL;
    }

    if (g_ahlog) {
        fclose(g_ahlog);
        g_ahlog = NULL;
    }

    FILE* log = fopen("crypto_logger.log", "a");
    fprintf(log, "[*] CryptoLogger cleanup complete\n");
    fclose(log);
}
