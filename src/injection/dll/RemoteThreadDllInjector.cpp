#include "injection/dll/RemoteThreadDllInjector.h"

RemoteThreadDllInjector::RemoteThreadDllInjector(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath) {
	InjectInto(pi, dllPath);
}

RemoteThreadDllInjector::~RemoteThreadDllInjector() {}

bool RemoteThreadDllInjector::InjectInto(PROCESS_INFORMATION& pi, const std::filesystem::path& dllPath) {
	try {
		dllPathAddress = _AllocateRemoteMemory(pi.hProcess, dllPath.wstring().size() + 1);
		_WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), dllPath.wstring().size() + 1);

		// Modularizar mas adelante... asquito estando aqui.
		HMODULE localKernelBase = GetModuleHandleW(L"kernel32.dll");
		FARPROC localLoadLibraryW = GetProcAddress(localKernelBase, "LoadLibraryW");

		hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)localLoadLibraryW, dllPathAddress, 0, NULL);

		// WaitForSingleObject(hRemoteThread, INFINITE);

		return true;
	}
	catch (const std::exception& e) {
		Logger::error(std::string("Issues while trying DLL injection. Reason: ") + e.what());
	}

	return false;
}

bool RemoteThreadDllInjector::_CreateRemoteProcessLoaderThread(HANDLE hProcess, SIZE_T size) {
    return false;
}

void RemoteThreadDllInjector::_WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size) {
	if (!WriteProcessMemory(hProcess, remoteAddress, buffer, size, NULL)) {
		Logger::error("It wasn't possible to write DLL path on the remote memory. Reason: " );
		//std::cerr << "Error escribiendo la ruta del DLL en la memoria remota: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteAddress, 0, MEM_RELEASE);
		throw std::runtime_error("It wasn't possible to write DLL path on the remote memory.");
	}
}

LPVOID RemoteThreadDllInjector::_AllocateRemoteMemory(HANDLE hProcess, SIZE_T size) {
	LPVOID remoteMemory = api.VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMemory == NULL) {
		std::cerr << "Error asignando memoria para la ruta del DLL en el proceso remoto: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria para la ruta del DLL en el proceso remoto");
	}

	return remoteMemory;
}

LPVOID RemoteThreadDllInjector::GetDllPathAddress() {
	return dllPathAddress;
}

HANDLE RemoteThreadDllInjector::GetHRemoteThread() {
	return hRemoteThread;
}

