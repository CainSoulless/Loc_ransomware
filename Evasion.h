#pragma once

#include <windows.h>
#include "Executable.h"
#include <iostream>

extern DWORD	ErrorValue(void);
extern BYTE		checkDebugger(void);

class Evasion {
public:
	Evasion();
	Executable process;
	BOOL isBeingDebugging(void);
};