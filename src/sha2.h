#pragma once

/* Secure Hash Algorithms 2
 * Design: NSA
 * Standard: FIPS PUB 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)
 */

#include "hashbase.h"

namespace crypto
{
    namespace sha2
    {
        typedef u64 state512;
        typedef u32 state256;
    }

    template<size_t digestSize, typename opType, bool generator512 = false>
    class SHA : public IHashFunction<digestSize>
    {
    public:
        SHA();
        void operator()(const u8* message, const size_t& size, u8* digest);
        void init();
        void update(const u8* data, const size_t& size);
        void final(u8* data);
    private:
        static constexpr bool width32 = sizeof(opType) == sizeof(u32);
        opType H[8];
        u8 block[width32 ? 64 : 128];
        u64 sumInputSize = 0;
        void roundFunction(u8* data);
    protected:

    };

    typedef SHA<256, sha2::state256> SHA256;
    typedef SHA<224, sha2::state256> SHA224;
    typedef SHA<384, sha2::state512> SHA384;
    typedef SHA<512, sha2::state512> SHA512;
    typedef SHA<224, sha2::state512> SHA512_224;
    typedef SHA<256, sha2::state512> SHA512_256;
}