#pragma once
#include <vector>
#include <string>

class Obfuscator {
public:
	static std::string DecryptCaesar(std::vector<unsigned char>& data, int key);
};
