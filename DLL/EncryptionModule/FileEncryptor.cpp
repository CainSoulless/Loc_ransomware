#include "pch.h"
#include "FileEncryptor.h"
#include <fstream>
#include <iterator>

FileEncryptor::FileEncryptor(char xorKey) : xorKey(xorKey) {}

std::vector<char> FileEncryptor::XORFile(const fs::path& filePath) const {
    std::ifstream input(filePath, std::ios::binary);
    if (!input.is_open()) return {};

    std::vector<char> data((std::istreambuf_iterator<char>(input)), {});
    input.close();

    return XORBuffer(data);
}

std::vector<char> FileEncryptor::XORBuffer(const std::vector<char>& input) const {
    std::vector<char> result = input;
    for (char& byte : result) byte ^= xorKey;
    return result;
}
