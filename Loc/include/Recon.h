#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
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
	static	HANDLE	getProcessSnapshot();
	std::wstring getHomeFolder();
};