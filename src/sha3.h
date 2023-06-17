#pragma once

/* Secure Hash Algorithms 3 / Keccak
 * Design: Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 * Standard: FIPS PUB 202-4 (https://csrc.nist.gov/publications/detail/fips/202/final)
 */

#include "hashbase.h"

namespace crypto
{
	template<size_t digestSize>
	class SHA3 : public IHashFunction<digestSize>
	{
	public:
		SHA3();
		void operator()(const u8* message, const size_t& size, u8* digest);
		void init();
		void update(const u8* data, const size_t& size);
		void final(u8* data);
	private:
		static constexpr size_t
			roundCount = 24,
			bBits = 1600, bBytes = bBits / 8,
			wBits = 64, wBytes = wBits / 8,
			rBits = bBits - (digestSize * 2), rBytes = rBits / 8;
		u8 state[bBytes];
		size_t sumInputSize;
	protected:

	};

	typedef SHA3<224> SHA3_224;
	typedef SHA3<256> SHA3_256;
	typedef SHA3<384> SHA3_384;
	typedef SHA3<512> SHA3_512;
}