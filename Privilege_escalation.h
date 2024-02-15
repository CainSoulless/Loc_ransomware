#pragma once
#include <windows.h>
#include <xstring>

class Privilege_escalation {
private:
	std::wstring current_username;
	std::wstring current_password;
public:
	Privilege_escalation();
	BOOL getCredentialsByAutoAdminLogon(HKEY hkey);
	BOOL extractCredValue(HKEY hkey, LPCWSTR registryKeyValue, std::wstring &credential);
	HKEY existsAutoAdminLogon();
};