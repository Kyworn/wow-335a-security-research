#ifndef MEMORY_READER_H
#define MEMORY_READER_H

#include <windows.h>
#include <stdint.h>

// WoW 3.3.5a Object Manager structures
#define OBJECT_TYPE_ITEM 1
#define OBJECT_TYPE_CONTAINER 2
#define OBJECT_TYPE_UNIT 3
#define OBJECT_TYPE_PLAYER 4
#define OBJECT_TYPE_GAMEOBJECT 5
#define OBJECT_TYPE_DYNAMICOBJECT 6
#define OBJECT_TYPE_CORPSE 7

// Start memory scanning and logging
void StartMemoryScanning(void);
void StopMemoryScanning(void);

// Scan for specific patterns (AH data, gold, items, etc.)
void ScanForAuctionHouseData(void);
void ScanForPlayerGold(void);
void ScanForInventory(void);

#endif
