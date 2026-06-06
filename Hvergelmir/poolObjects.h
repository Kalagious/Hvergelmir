#pragma once
#include "includes.h"

struct FILE_PIPE_ATTRIBUTE_BUFFER {
    ULONG AttributeNameLength;   // +0x00
	ULONG AttributeValueLength;  // +0x04
	CHAR AttributeName[1];       // +0x08
};

struct IRPBuffer {
    UINT32 pid;                  // +0x00
	UINT32 ppid;                 // +0x04
	BYTE data[];                 // +0x08
};


struct IRP {
    BYTE  padding[0x18];      // +0x00
	PVOID SystemBuffer;       // +0x18
};


struct NP_DATA_QUEUE_ENTRY {
    LIST_ENTRY NextEntry;      // +0x00
	IRP* Irp;                  // +0x10
	UINT64 SecurityContext;    // +0x18
	ULONG EntryType;           // +0x20
	ULONG QuotaInEntry;        // +0x24
	ULONG DataSize;            // +0x28
	ULONG Reserved;            // +0x2C
	char  Data;                // +0x30
};


struct LFH_POOL_HEADER
{
    BYTE previousSize = 0x00;        // +0x00
	BYTE poolIndex = 0x00;           // +0x01
	BYTE blockSize = 0x00;           // +0x02
	BYTE poolType = 0x00;            // +0x03
	UINT32 poolTag = 0x00000000;           // +0x04
	UINT64 poolQuota = 0x0000000000000000;        // +0x08
};

struct LFH_NP_DATA_QUEUE_ENTRY {
    LFH_POOL_HEADER poolHeader;     // +0x00
	NP_DATA_QUEUE_ENTRY dataQueue; // +0x10

};


struct IOP_MC_BUFFER_ENTRY {
	USHORT Type;                 // +0x00
	USHORT Size;                 // +0x02
	ULONG ReferenceCount;        // +0x04
	ULONG Flags;                 // +0x08
	LIST_ENTRY GlobalDataLink;   // +0x10
	PVOID Address;               // +0x20
	ULONG Length;                // +0x28
	CHAR AccessMode;             // +0x2C
	UCHAR MdlRef;                // +0x2D 
	USHORT Pad;                  // +0x2E
};