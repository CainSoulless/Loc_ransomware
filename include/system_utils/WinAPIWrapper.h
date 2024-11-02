#pragma once

#include <windows.h>
#include <iostream>
#include <vector>

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)

class WinAPIWrapper {
public:
	WinAPIWrapper();
	~WinAPIWrapper();

    
    BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
        LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation);

    LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

    BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);

    NTSTATUS NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

    BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext);

    BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead);

    BOOL SetThreadContext(HANDLE hThread, const CONTEXT* lpContext);

    DWORD ResumeThread(HANDLE hThread);
private:
	HMODULE hKernel32 = nullptr;
	HMODULE hNtdll = nullptr;

    using pCreateProcessA = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    using pVirtualAllocEx = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    using pWriteProcessMemory = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    using pNtUnmapViewOfSection = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    using pGetThreadContext = BOOL(WINAPI*)(HANDLE, LPCONTEXT);
    using pReadProcessMemory = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    using pSetThreadContext = BOOL(WINAPI*)(HANDLE, const CONTEXT*);
    using pResumeThread = DWORD(WINAPI*)(HANDLE);

    pCreateProcessA CreateProcessA_             = nullptr;
    pVirtualAllocEx VirtualAllocEx_             = nullptr;
    pWriteProcessMemory WriteProcessMemory_     = nullptr;
    pNtUnmapViewOfSection NtUnmapViewOfSection_ = nullptr;
    pGetThreadContext GetThreadContext_         = nullptr;
    pReadProcessMemory ReadProcessMemory_       = nullptr;
    pSetThreadContext SetThreadContext_         = nullptr;
    pResumeThread ResumeThread_                 = nullptr;

    void _LoadFunctions();
    
};