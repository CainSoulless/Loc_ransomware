#ifndef ASM_FUNCTIONS_H
#define ASM_FUNCTIONS_H

#include <Windows.h>
#include <minwindef.h>
#include <winternl.h>

extern "C" {
	PTEB		TEBValue(void);
	PPEB		PEBValue(void);
	BYTE		checkDebugger(void);
	DWORD		ErrorValue(void);
}

#endif // ASM_FUNCTIONS_H