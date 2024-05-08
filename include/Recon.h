#pragma once
#include <Windows.h>
#include <string>
#include <Shlobj.h>

class Recon {
private:
	struct WindowsVersion  {
		DWORD majorVersion;
		DWORD minorVersion;
		DWORD buildNumber;
	} ;
	WindowsVersion windowsVersion;

	std::wstring homeFolder;

public:
	Recon();
	DWORD	getMajorVersion();
	DWORD	getMinorVersion();
	DWORD	getBuildNumber();
	VOID	setWindowsVersion();
	VOID	setHomeFolder();
	std::wstring getHomeFolder();
};