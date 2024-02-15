#pragma once
#include <minwindef.h>
#include <winternl.h>

extern "C" PTEB	TEBValue(void);
extern "C" PPEB	PEBValue(void);
extern "C" BYTE	checkDebugger(void);