#include "injection/dll/RemoteThreadDllInjector.h"

RemoteThreadDllInjector::RemoteThreadDllInjector() {}

RemoteThreadDllInjector::~RemoteThreadDllInjector() {}

bool RemoteThreadDllInjector::InjectInto(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath) noexcept {
	try {
		dllPathAddress = _AllocateRemoteMemory(pi.hProcess, dllPath.wstring().size() + 1);
		_WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), dllPath.wstring().size() + 1);
		hRemoteThread = api.CreateRemoteThread(pi.hProcess, NULL, 0, NULL, dllPathAddress, 0, NULL);

		return true;
	}
	catch (const std::exception& e) {
		Logger::error(std::string("Issues while trying DLL injection. Reason: ") + e.what());
	}

	return false;
}

LPVOID RemoteThreadDllInjector::GetDllPathAddress() {
	return dllPathAddress;
}

HANDLE RemoteThreadDllInjector::GetHRemoteThread() {
	return hRemoteThread;
}

