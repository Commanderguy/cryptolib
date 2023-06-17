#include <random>
#include <chrono>

#include "src/debugutil.h"

#include "src/md5.h"
#include "src/sha2.h"
#include "src/sha3.h"

using namespace crypto;

template<size_t digestSize>
void printHashHex(IHashFunction<digestSize>* hashFunc, const char* message)
{
	crypto::u8 digest[digestSize / 8];
	hashFunc->init();
	hashFunc->update(reinterpret_cast<const crypto::u8*>(message), strlen(message));
	hashFunc->final(digest);

	for (int i = 0; i < (digestSize / 8); i++)
	{
		std::cout << digest[i];
	}
	std::cout << std::endl;
}

int main()
{
	crypto::md5 md5Prov;
	crypto::SHA256 sha2Prov;
	crypto::SHA3_256 sha3Prov;

	std::cout << "md5:  ";
	printHashHex(&md5Prov, "");
	std::cout << "\nsha2: ";
	printHashHex(&sha2Prov, "");
	std::cout << "\nsha3: ";
	printHashHex(&sha3Prov, "");
}