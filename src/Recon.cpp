#include <stdint.h>
#include "Recon.h"

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