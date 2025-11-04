#pragma once
#include <filesystem>
#include <system_error>
#include <windows.h>
#include "Logger.h"
#include "system_utils/WinAPIWrapper.h"

class IInjector {
public:
	virtual ~IInjector() = default;

	/*
	virtual bool InjectInto(
		PROCESS_INFORMATION& pci,
		const std::filesystem::path& dllPath) noexcept = 0;

	virtual bool InjectInto(
		PROCESS_INFORMATION& pci,
		const std::vector<unsigned char>& shellcode) noexcept = 0;
	*/
protected:
	LPVOID _AllocateRemoteMemory(HANDLE hProcess, SIZE_T size);
	void _WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size);
	WinAPIWrapper api;
};
