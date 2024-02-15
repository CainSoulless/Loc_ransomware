#pragma once

#include "ASM.h"

class Executable {
public:
    Executable();
    BOOL    beingDebugged();
    LPCWSTR getCurrentPath();
    PTEB    getTEB();
    PPEB    getPEB();
    
private:
    LPCWSTR currentPath;
    PTEB    pTEB = TEBValue();
    PPEB    pPEB = PEBValue();
};