#include <stdint.h>
#include "Recon.h"
#include "HandleGuard.h"

Recon::Recon() {
	Recon::setWindowsVersion();
	Recon::setHomeFolder();
}

VOID Recon::setWindowsVersion() {
	DWORD kuser_address = 0x7ffe0000;

	this->windowsVersion.majorVersion	= *((DWORD*)(uintptr_t)(kuser_address + 0x26C));
	this->windowsVersion.minorVersion	= *((DWORD*)(uintptr_t)(kuser_address + 0x270));
	this->windowsVersion.buildNumber	= *((DWORD*)(uintptr_t)(kuser_address + 0x260));
}

DWORD Recon::getMajorVersion() {
	return this->windowsVersion.majorVersion;
}

DWORD Recon::getMinorVersion() {
	return this->windowsVersion.majorVersion;
}

DWORD Recon::getBuildNumber() {
	return this->windowsVersion.buildNumber;
}

VOID Recon::setHomeFolder() {
	PWSTR pszPath;

	if (SHGetKnownFolderPath(FOLDERID_Profile, 0, NULL, &pszPath) == S_OK) {
		std::wstring personalFolderPath(pszPath);
		CoTaskMemFree(pszPath);
		
		this->homeFolder = personalFolderPath;
	}
	
	return;
}

std::wstring Recon::getHomeFolder() {
	return this->homeFolder;
}

HANDLE Recon::getProcessSnapshot(void) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "INVALID_HANDLE_VALUE" << std::endl;
		return NULL;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnapshot, &pe32)) {
		std::cerr << "Issues getting de process snapshot." << std::endl;
		CloseHandle(hSnapshot);
		return NULL;
	}
	
	return hSnapshot;
}