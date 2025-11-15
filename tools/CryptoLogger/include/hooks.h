#ifndef HOOKS_H
#define HOOKS_H

#include <windows.h>
#include <stdint.h>

// Initialisation
BOOL InitHooks(void);
void CleanupHooks(void);

// Hooks réseau
BOOL HookRecv(void);
BOOL HookSend(void);

// Hooks crypto (à implémenter après détection)
BOOL HookRC4Init(void* address);
BOOL HookRC4Process(void* address);

// Logging
void InitLogs(void);
void LogRawPacket(const char* direction, const unsigned char* buf, int len);
void LogSessionKey(const unsigned char* key, size_t keylen);

// Memory scanner
void ScanProcessMemory(void);
void TriggerMemoryScanOnLogin(int packet_size);

// Structures WoW
#pragma pack(push, 1)
typedef struct {
    uint16_t size;
    uint32_t opcode;
} WoWPacketHeader;

typedef struct {
    uint32_t auction_id;
    uint32_t item_template;
    uint32_t item_random_property;
    uint32_t item_suffix_factor;
    uint32_t item_count;
    uint32_t spell_charges;
    uint32_t flags;
    uint64_t owner_guid;
    uint32_t start_bid;
    uint32_t min_bid;
    uint32_t buyout_price;
    uint32_t time_left;
    uint64_t bidder_guid;
    uint32_t current_bid;
} AuctionEntry;
#pragma pack(pop)

// Opcodes WoW (WotLK 3.3.5a - à vérifier pour Ascension)
#define CMSG_PING                       0x01DC
#define CMSG_AUCTION_HELLO              0x0255
#define CMSG_AUCTION_LIST_ITEMS         0x0257
#define CMSG_AUCTION_LIST_BIDDER_ITEMS  0x0264
#define CMSG_AUCTION_LIST_OWNER_ITEMS   0x0258

#define SMSG_PONG                       0x01DD
#define SMSG_AUCTION_HELLO              0x024B
#define SMSG_AUCTION_LIST_RESULT        0x025B
#define SMSG_AUCTION_BIDDER_LIST_RESULT 0x0265
#define SMSG_AUCTION_OWNER_LIST_RESULT  0x025D

#endif // HOOKS_H
