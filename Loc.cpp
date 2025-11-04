// Loc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define TEST_MODE 1

#if TEST_MODE == 1
#include "tests/test.h"
#endif

int main(void) {
	//ShowWindow(GetConsoleWindow(), SW_HIDE);

    #if TEST_MODE == 1 
        start_testing();
        exit(0);
    #endif

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

