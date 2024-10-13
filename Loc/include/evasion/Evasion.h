#pragma once

#include <iostream>

#include "Executable.h"
#include "Injection.h"
#include <winternl.h>

class HandleGuard;

typedef BOOL(WINAPI* VirtualProtect_t)(
	LPVOID,
	SIZE_T,
	DWORD,
	PDWORD);

class Evasion {
public:
	// Attributes
	BOOL mustBeAvoided;

	// Methods 
	Evasion();
	Executable process;
	BOOL isBeingDebugging(void);
	BOOL isDomainReachable(void);
};