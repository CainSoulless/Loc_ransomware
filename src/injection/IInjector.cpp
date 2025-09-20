#pragma once
#include "injection/IInjector.h"

void IInjector::_WriteRemoteMemory(HANDLE hProcess, LPVOID remoteAddress, const void* buffer, SIZE_T size) {
	if (!WriteProcessMemory(hProcess, remoteAddress, buffer, size, NULL)) {
		Logger::error("It wasn't possible to write DLL path on the remote memory. Reason: ");
		//std::cerr << "Error escribiendo la ruta del DLL en la memoria remota: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remoteAddress, 0, MEM_RELEASE);
		throw std::runtime_error("It wasn't possible to write DLL path on the remote memory.");
	}
}

LPVOID IInjector::_AllocateRemoteMemory(HANDLE hProcess, SIZE_T size) {
	LPVOID remoteMemory = api.VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (remoteMemory == NULL) {
		std::cerr << "Error asignando memoria para la ruta del DLL en el proceso remoto: " << GetLastError() << std::endl;
		throw std::runtime_error("Error asignando memoria para la ruta del DLL en el proceso remoto");
	}

	return remoteMemory;
}