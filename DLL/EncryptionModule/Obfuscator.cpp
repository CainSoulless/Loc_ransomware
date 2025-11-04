#include "pch.h"
#include "Obfuscator.h"

std::string Obfuscator::decryptCaesar(const std::vector<unsigned char>& data, int key) {
    std::vector<unsigned char> decrypted(data);

    for (size_t i = 0; i < decrypted.size(); ++i) {
        decrypted[i] = static_cast<unsigned char>((decrypted[i] + (0x100 - key)) % 0x100);
    }

    return std::string(decrypted.begin(), decrypted.end());
}

