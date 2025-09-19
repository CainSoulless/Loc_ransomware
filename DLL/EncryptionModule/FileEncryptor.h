#pragma once
#include <vector>
#include <string>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

class FileEncryptor
{
public:
	FileEncryptor(char xorKey);

	std::vector<char> XORFile(const fs::path& filePath) const;
	std::vector<char> XORBuffer(const std::vector<char>& input) const;

	//static std::string  encryptCaesar
private:
	const char xorKey;
};

