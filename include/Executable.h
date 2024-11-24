#pragma once
#include <windows.h>
#include <winternl.h>
#include <minwindef.h>

extern "C" {
    BYTE    checkDebugger(void);
    DWORD   ErrorValue(void);
    PTEB    TEBValue(void);
    PPEB    PEBValue(void);
}
class Executable {
public:
    Executable();
    BOOL    beingDebugged();
    static LPCWSTR getCurrentPath();
    PTEB    getTEB();
    PPEB    getPEB();
    
private:
    LPCWSTR currentPath;
    PTEB    pTEB = TEBValue();
    PPEB    pPEB = PEBValue();
};