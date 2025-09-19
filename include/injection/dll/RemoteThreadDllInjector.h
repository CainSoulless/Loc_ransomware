#pragma once
//#include "injection/dll/IDllInjector.h"
#include "system_utils/WinAPIWrapper.h"
#include "Logger.h"
#include <cstddef>
#include <filesystem>

class RemoteThreadDllInjector {
public:
	RemoteThreadDllInjector(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath);
	~RemoteThreadDllInjector();

	bool InjectInto(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath);
	LPVOID GetDllPathAddress();
	HANDLE GetHRemoteThread();


private:
	bool _CreateRemoteProcessLoaderThread(HANDLE hProcess, SIZE_T size);
	LPVOID _AllocateRemoteMemory(HANDLE hProcess, SIZE_T size);
	void _WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size);

	WinAPIWrapper api;
	LPVOID dllPathAddress = NULL;
	HANDLE hRemoteThread = NULL;
};

