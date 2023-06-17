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
	crypto::SHA224 sha224Prov;

	std::cout << "md5: ";

}