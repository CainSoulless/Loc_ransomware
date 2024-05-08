#pragma once

#include <Windows.h>
#include <winternl.h>
#include <minwindef.h>

extern "C" {
	BYTE		checkDebugger(void);
	DWORD		ErrorValue(void);
	PTEB		TEBValue(void);
	PPEB		PEBValue(void);
}