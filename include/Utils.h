#pragma once

#include <string>
#include <iostream>
#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

class Utils {
public:
	Utils();
	void changeWallpaper();
	static BOOL HostConnection(const std::string& hostname, int port);
	static std::string getRandomDomain(void);
	static std::string generateRandomString(void);
	static std::wstring StringToWstring(const std::string& str);
};