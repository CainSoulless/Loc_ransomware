#pragma once

#include "Executable.h"
#include <iostream>
#include <Windows.h>

class Evasion {
public:
	Evasion();
	Executable process;
	BOOL isBeingDebugging(void);
};