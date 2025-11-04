#pragma once
#include "injection/dll/IDllInjector.h"
#include "Logger.h"
#include <cstddef>
#include <filesystem>

class RemoteThreadDllInjector : public IDllInjector {
public:
	RemoteThreadDllInjector();
	~RemoteThreadDllInjector();

	//bool InjectInto(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath) noexcept override;
	bool InjectInto(PROCESS_INFORMATION& pi, const std::wstring& dllPath) noexcept override;
	LPVOID GetDllPathAddress();
	HANDLE GetHRemoteThread();


private:
	LPVOID dllPathAddress = NULL;
	HANDLE hRemoteThread = NULL;
};

