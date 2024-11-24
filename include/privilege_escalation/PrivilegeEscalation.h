#pragma once

#include <windows.h>
#include <xstring>
#include <string>
#include <vector>
#include "HandleGuard.h"

class PrivilegeEscalation {
private:
	std::wstring current_username;
	std::wstring current_password;
public:
	PrivilegeEscalation();
	BOOL getCredentialsByAutoAdminLogon(HKEY hkey);
	BOOL extractCredValue(HKEY hkey, LPCWSTR registryKeyValue, std::wstring& credential);
	HKEY existsAutoAdminLogon();
	static BOOL enableDebugPrivilege();
	BOOL TokenImpersonationSucceed();
};