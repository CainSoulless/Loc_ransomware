#pragma once

#include <iostream>
#include "Executable.h"

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
	int unhookNtdll(const HMODULE hNtdll, const LPVOID pMapping);
};