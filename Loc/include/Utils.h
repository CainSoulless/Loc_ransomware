#pragma once

#include <string>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

class Utils {
public:
	Utils();
	void changeWallpaper();
	static BOOL hostConnection(const std::string& hostname, int port);
	static std::string getRandomDomain(void);
	static std::string generateRandomString(void);
};