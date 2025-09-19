#pragma once
#include <vector>
#include <string>
#include "pch.h"

class Obfuscator {
public:
	static std::string decryptCaesar(const std::vector<unsigned char>& data, int key);
};
