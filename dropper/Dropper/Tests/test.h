#pragma once
#include <windows.h>
#include <iostream>

void start_testing() {
	char sysDir[MAX_PATH];
	GetSystemDirectoryA(sysDir, MAX_PATH);

	std::cout << sysDir << std::endl;
}