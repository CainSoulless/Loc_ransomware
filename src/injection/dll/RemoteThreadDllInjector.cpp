#include "injection/dll/RemoteThreadDllInjector.h"

RemoteThreadDllInjector::RemoteThreadDllInjector() {}

RemoteThreadDllInjector::~RemoteThreadDllInjector() {}

bool RemoteThreadDllInjector::InjectInto(PROCESS_INFORMATION& pi, const std::wstring& dllPath) noexcept {
	try {
        SIZE_T pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
		dllPathAddress = _AllocateRemoteMemory(pi.hProcess, pathSize);
		_WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), pathSize);
		hRemoteThread = api.CreateRemoteThread(pi.hProcess, NULL, 0, NULL, dllPathAddress, 0, NULL);

		return true;
	}
	catch (const std::exception& e) {
		Logger::error(std::string("Issues while trying DLL injection. Reason: ") + e.what());
	}

	return false;
}
/*
bool RemoteThreadDllInjector::InjectInto(PROCESS_INFORMATION& pi, const std::wstring& dllPath) noexcept {
    try {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        LPTHREAD_START_ROUTINE loadLib = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

        SIZE_T pathSize = (dllPath.size() + 1) * sizeof(wchar_t);

        dllPathAddress = _AllocateRemoteMemory(pi.hProcess, pathSize);
        _WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), pathSize);

        // NULL = el wrapper usa LoadLibraryW automáticamente
        //hRemoteThread = api.CreateRemoteThread(pi.hProcess, NULL, 0,
        //    NULL, dllPathAddress, 0, NULL);

        hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, loadLib, dllPathAddress, 0, NULL);

        if (!hRemoteThread) {
            throw std::runtime_error("Error creando thread remoto: " + std::to_string(GetLastError()));
        }

        return true;
    }
    catch (const std::exception& e) {
        Logger::error(std::string("Issues while trying DLL injection. Reason: ") + e.what());
        if (dllPathAddress && pi.hProcess) {
            VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);
        }
    }
    return false;
}
*/
LPVOID RemoteThreadDllInjector::GetDllPathAddress() {
	return dllPathAddress;
}

HANDLE RemoteThreadDllInjector::GetHRemoteThread() {
	return hRemoteThread;
}

