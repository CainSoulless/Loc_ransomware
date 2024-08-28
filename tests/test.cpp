#include "Crypt.h"
#include <iostream>

void start_testing(void) {
	//Injection injection;

	////injection.decryptShellcode();
	//injection.backdoorInjection();
	
	Crypt crypt;

	crypt.startCrypt();

	//std::vector<unsigned char> test = { '.', 'l', 'o', 'c' };

	//std::string new_test = crypt.encryptCaesar(test, 0xDE);

	//for (unsigned char c : new_test) {
	//	std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << " ";
	//}
	//std::cout << std::dec << std::endl; // Restaurar formato decimal
}