#include "Hvergelmir.h"



bool Hvergelmir::VerifySystem() {

	if (!PrimeOverflow || !TriggerOverflow || !PassOverflow) {
		DEBUG_PRINT(" [!] One or more overflow function pointers are null\n");
		return false;
	}


	systemVerified = true;
	return true;
}

bool Hvergelmir::SetOverflowFunctions(std::function<void(UINT64)> iPrimeOverflow, std::function<void(BYTE*, UINT64)> iTriggerOverflow, std::function<void()> iPassOverflow)
{
	if (!iPrimeOverflow || !iTriggerOverflow || !iPassOverflow) {
		DEBUG_PRINT(" [!] One or more overflow function pointers are null\n");
		return false;
	}

	PrimeOverflow = iPrimeOverflow;
	TriggerOverflow = iTriggerOverflow;
	PassOverflow = iPassOverflow;
	return true;
}



bool Hvergelmir::Cleanup() {

	return true;
}

