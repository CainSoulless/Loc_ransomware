#include "Obfuscator.h"

std::string Obfuscator::DecryptCaesar(std::vector<unsigned char>& data, int key) {
	for (size_t i = 0; i < data.size(); i++) {
		data[i] = static_cast<unsigned char>((data[i] + (0x100 - key)) % 0x100);
	}

	std::string str(data.begin(), data.end());
	str.push_back('\0');

	return str;
}

