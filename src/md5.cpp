#include "md5.h"

#include <cstring>

using namespace crypto;

crypto::md5::md5()
{
    init();
}

crypto::md5::md5(const md5& other)
{
    memcpy(this->block, other.block, blockSize);
    this->A = other.A;
    this->B = other.B;
    this->C = other.C;
    this->D = other.D;
    sumInputSize = other.sumInputSize;
}

crypto::md5::md5(md5&& other) noexcept
{
    memcpy(this->block, other.block, blockSize);
    this->A = other.A;
    this->B = other.B;
    this->C = other.C;
    this->D = other.D;
    sumInputSize = other.sumInputSize;

    memset(other.block, 0, blockSize);
    other.A = 0x67452301;
    other.B = 0xefcdab89;
    other.C = 0x98badcfe;
    other.D = 0x10325476;
    other.sumInputSize = 0;
}

void crypto::md5::init()
{
    A = 0x67452301; 
    B = 0xefcdab89; 
    C = 0x98badcfe; 
    D = 0x10325476;

    sumInputSize = 0;
    memset(block, 0, blockSize);
}

void crypto::md5::update(const u8* data, const size_t& size)
{
    u64 mutSize = size;
    u8* byteData = const_cast<u8*>(data);
    u64 blockPtr = (sumInputSize % blockSize);
    u64 bytesNeeded = blockSize - blockPtr;

    if (blockPtr != 0 && bytesNeeded > size)
    {
        memcpy(block + blockPtr, data, size);
        return;
    }
    else if (blockPtr != 0 && bytesNeeded < size)
    {
        memcpy(block + blockPtr, data, bytesNeeded);
        roundFunction(block);
        byteData += bytesNeeded;
        mutSize -= bytesNeeded;
    }
    for (size_t i = 0; i < (size / blockSize); i++)
    {
        roundFunction(byteData);
        byteData += blockSize;
        mutSize -= blockSize;
    }

    memcpy(block, byteData, mutSize);
    sumInputSize += size;
}

void crypto::md5::final(u8* data)
{
    u64 blockPtr = (sumInputSize % blockSize);

    if (blockPtr <= 55)
    {
        block[blockPtr] = 0x80;
        memset(block + 1 + blockPtr, 0, blockSize - 9 - blockPtr);

        size_t sumInputSizeBits = sumInputSize * 8;

        block[56] = static_cast<u8>(sumInputSizeBits >> 0);
        block[57] = static_cast<u8>(sumInputSizeBits >> 8);
        block[58] = static_cast<u8>(sumInputSizeBits >> 16);
        block[59] = static_cast<u8>(sumInputSizeBits >> 24);
        block[60] = static_cast<u8>(sumInputSizeBits >> 32);
        block[61] = static_cast<u8>(sumInputSizeBits >> 40);
        block[62] = static_cast<u8>(sumInputSizeBits >> 48);
        block[63] = static_cast<u8>(sumInputSizeBits >> 56);
    }
    else
    {
        block[blockPtr] = 0x80;
        memset(block + blockPtr + 1, 0, blockSize - blockPtr - 1);

        roundFunction(block);

        memset(block, 0, blockSize - 8);

        size_t sumInputSizeBits = sumInputSize * 8;

        block[56] = static_cast<u8>(sumInputSizeBits >> 0);
        block[57] = static_cast<u8>(sumInputSizeBits >> 8);
        block[58] = static_cast<u8>(sumInputSizeBits >> 16);
        block[59] = static_cast<u8>(sumInputSizeBits >> 24);
        block[60] = static_cast<u8>(sumInputSizeBits >> 32);
        block[61] = static_cast<u8>(sumInputSizeBits >> 40);
        block[62] = static_cast<u8>(sumInputSizeBits >> 48);
        block[63] = static_cast<u8>(sumInputSizeBits >> 56);
    }
    
    roundFunction(block);

    u32* out = reinterpret_cast<u32*>(data);

    out[0] = A;
    out[1] = B;
    out[2] = C;
    out[3] = D;

    init();
}

void crypto::md5::operator()(const u8* message, const size_t& size, u8* digest)
{
    init();
    update(message, size);
    final(digest);
}

#define R1(a, b, c, d, k, s, i) {a = b + crotl<s, u32>(a + (b & c | ~b & d) + wordData[k] + T[i]);}
#define R2(a, b, c, d, k, s, i) {a = b + crotl<s, u32>(a + (b & d | c & ~d) + wordData[k] + T[i]);}
#define R3(a, b, c, d, k, s, i) {a = b + crotl<s, u32>(a + (b ^ c ^ d) + wordData[k] + T[i]);}
#define R4(a, b, c, d, k, s, i) {a = b + crotl<s, u32>(a + (c ^ (b | ~d)) + wordData[k] + T[i]);}

void crypto::md5::roundFunction(u8* data)
{
    const u32* wordData = reinterpret_cast<u32*>(data);

    u32 AA = A;
    u32 BB = B;
    u32 CC = C;
    u32 DD = D;

    // Precomputed
    constexpr u32 T[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

    R1(A, B, C, D,  0, 7,  0); R1(D, A, B, C,  1, 12,  1); R1(C, D, A, B,  2, 17,  2); R1(B, C, D, A,  3, 22,  3);
    R1(A, B, C, D,  4, 7,  4); R1(D, A, B, C,  5, 12,  5); R1(C, D, A, B,  6, 17,  6); R1(B, C, D, A,  7, 22,  7);
    R1(A, B, C, D,  8, 7,  8); R1(D, A, B, C,  9, 12,  9); R1(C, D, A, B, 10, 17, 10); R1(B, C, D, A, 11, 22, 11);
    R1(A, B, C, D, 12, 7, 12); R1(D, A, B, C, 13, 12, 13); R1(C, D, A, B, 14, 17, 14); R1(B, C, D, A, 15, 22, 15);

    R2(A, B, C, D,  1, 5, 16); R2(D, A, B, C,  6,  9, 17); R2(C, D, A, B, 11, 14, 18); R2(B, C, D, A,  0, 20, 19);
    R2(A, B, C, D,  5, 5, 20); R2(D, A, B, C, 10,  9, 21); R2(C, D, A, B, 15, 14, 22); R2(B, C, D, A,  4, 20, 23);
    R2(A, B, C, D,  9, 5, 24); R2(D, A, B, C, 14,  9, 25); R2(C, D, A, B,  3, 14, 26); R2(B, C, D, A,  8, 20, 27);
    R2(A, B, C, D, 13, 5, 28); R2(D, A, B, C,  2,  9, 29); R2(C, D, A, B,  7, 14, 30); R2(B, C, D, A, 12, 20, 31);

    R3(A, B, C, D,  5, 4, 32); R3(D, A, B, C,  8, 11, 33); R3(C, D, A, B, 11, 16, 34); R3(B, C, D, A, 14, 23, 35);
    R3(A, B, C, D,  1, 4, 36); R3(D, A, B, C,  4, 11, 37); R3(C, D, A, B,  7, 16, 38); R3(B, C, D, A, 10, 23, 39);
    R3(A, B, C, D, 13, 4, 40); R3(D, A, B, C,  0, 11, 41); R3(C, D, A, B,  3, 16, 42); R3(B, C, D, A,  6, 23, 43);
    R3(A, B, C, D,  9, 4, 44); R3(D, A, B, C, 12, 11, 45); R3(C, D, A, B, 15, 16, 46); R3(B, C, D, A,  2, 23, 47);

    R4(A, B, C, D,  0, 6, 48); R4(D, A, B, C,  7, 10, 49); R4(C, D, A, B, 14, 15, 50); R4(B, C, D, A,  5, 21, 51);
    R4(A, B, C, D, 12, 6, 52); R4(D, A, B, C,  3, 10, 53); R4(C, D, A, B, 10, 15, 54); R4(B, C, D, A,  1, 21, 55);
    R4(A, B, C, D,  8, 6, 56); R4(D, A, B, C, 15, 10, 57); R4(C, D, A, B,  6, 15, 58); R4(B, C, D, A, 13, 21, 59);
    R4(A, B, C, D,  4, 6, 60); R4(D, A, B, C, 11, 10, 61); R4(C, D, A, B,  2, 15, 62); R4(B, C, D, A,  9, 21, 63);

    A = A + AA;
    B = B + BB;
    C = C + CC;
    D = D + DD;
}

#undef R1
#undef R2
#undef R3
#undef R4