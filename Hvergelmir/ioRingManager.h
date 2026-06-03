#pragma once
#include "includes.h"


class IORingManager {
public:
	UINT64 ioRingCount;

	HIORING* ioRings;
	HIORING corruptedRing;

	UINT64* corruptedRingOriginalData;
	UINT64 corruptedRingEntryAddr;

	IORingManager();
	HIORING CreateRing();
	void CreateRings(UINT64 iCount);
	void ClearRings();


	void TriggerCorruptRing(UINT64 data, UINT64 payloadSize);

	std::vector<HIORING> ioRingVector;
	std::vector<BYTE*> registeredBuffers;


};

