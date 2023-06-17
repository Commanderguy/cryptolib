#pragma once

/* Message-Digest Algorithm 5
 * Design: Ronald Rivest 
 * Standard: RFC 1321 (https://www.ietf.org/rfc/rfc1321.txt)
 */

#include "hashbase.h"

namespace crypto
{
    class md5 : public IHashFunction<128>
    {
    public:
        md5();
        md5(const md5& other);
        md5(md5&& other) noexcept;
        void init();
        void update(const u8* data, const size_t& size);
        void final(u8* data);
        void operator()(const u8* message, const size_t& size, u8* digest);
    private:
        u8 block[64];
        u64 sumInputSize = 0;
        u32 A = 0x67452301, B = 0xefcdab89, C = 0x98badcfe, D = 0x10325476;

        void roundFunction(u8* data);

        static constexpr size_t blockSize = 64;
    protected:

    };
}