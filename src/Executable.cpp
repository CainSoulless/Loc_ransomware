#include "Windows.h"
#include "Executable.h"
#include <iostream>

Executable::Executable() {
    LPCWSTR path = Executable::getCurrentPath();
}

PTEB Executable::getTEB() {
    return this->pTEB;
}

PPEB Executable::getPEB() {
    return this->pPEB;
}

BOOL Executable::beingDebugged() {
    return (checkDebugger() == 0) ? FALSE : TRUE;
}

LPCWSTR Executable::getCurrentPath() {
    wchar_t buffer[MAX_PATH];
    DWORD length = GetModuleFileName(NULL, buffer, MAX_PATH);

    if (length > 0 && length < MAX_PATH) {
        return _wcsdup(buffer);
    }
    else {
        return L"";
    }
}

