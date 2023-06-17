#pragma once

#include "sha2.h"

#include <cstring>

using namespace crypto;

constexpr u64 initialValues[4][8] =
{
    {0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4}, // sha224
    {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}, // sha256
    {0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4}, // sha384
    {0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}, // sha512
};

constexpr u32 k32[64] =
{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

constexpr u64 k64[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

template<size_t digestSize, typename opType, bool generator512>
crypto::SHA<digestSize, opType, generator512>::SHA()
{
    init();
}

template<size_t digestSize, typename opType, bool generator512>
void crypto::SHA<digestSize, opType, generator512>::operator()(const u8* message, const size_t& size, u8* digest)
{
    init();
    update(message, size);
    final(digest);
}

template<size_t digestSize, typename opType, bool generator512>
inline void crypto::SHA<digestSize, opType, generator512>::init()
{
    static_assert(digestSize <= 512, "SHA2 digest size has to be smaller than 512.");
    static_assert((digestSize % 8) == 0, "This implememntation's SHA2 digest size has to be a multiple of 8.");
    constexpr size_t blockSize = width32 ? 64 : 128;

    sumInputSize = 0;
    memset(block, 0, blockSize);

    size_t ivIndex = 0;

    switch (digestSize)
    {
    case 224: ivIndex = 0; break;
    case 256: ivIndex = 1; break;
    case 384: ivIndex = 2; break;
    case 512: ivIndex = 3; break;
    }

    /*
    * SHA-512/t's initialization values are special as they are defined through
    * a function called the SHA-512/t IV Generation Function.
    * This Generation Function takes the string of the name of the hash function,
    * "SHA-512/t" where t is the number of bits the hash shall output and hashes it in a
    * special version of SHA-512, in which the IVs are being XORed by the hex value
    * 0xa5a5a5a5a5a5a5a5. The Output of that hash function then is used as the IV.
    * This function might be optimised heavily but as c++ has limited controllable compile
    * time capabilities to precompute function output I for now opted to reevaluate the IV's
    * for now, but that is far from optimal. Constexpr functions might be an option for
    * precomputing that value but that requires literal types as parameter types and return
    * types which pointers are not. Thus a seperate function would be needed with
    * std::arrays as parameters (or some similar constexpr container).
    */

    if (((digestSize == 224 && !width32) || (digestSize == 256 && !width32)) && digestSize != 512 && digestSize != 384)
    {
        /*
        * Constructing the string by hand avoids unneccessary dynamic allocation
        * and eleminates another security risk.
        */
        u8 sz = 8;
        u8 sha512tOutput[64];
        char istr[11] = { 'S', 'H', 'A', '-', '5', '1', '2', '/', 0, 0, 0 };

        if (digestSize > 99)
        {
            istr[sz] = '0' + (digestSize / 100);
            sz++;
        }

        if (digestSize > 9)
        {
            istr[sz] = '0' + (digestSize % 100) / 10;
            sz++;
        }
        istr[sz] = '0' + (digestSize % 10);
        sz++;

        SHA<512, sha2::state512, true> IvGenerator;

        IvGenerator.init();
        IvGenerator.update(reinterpret_cast<u8*>(istr), sz);
        IvGenerator.final(sha512tOutput);

        for (int i = 0, j = 0; i < 8; i++, j += 8)
        {
            H[i] = (static_cast<u64>(sha512tOutput[j + 7]) << 0)
                | (static_cast<u64>(sha512tOutput[j + 6]) << 8)
                | (static_cast<u64>(sha512tOutput[j + 5]) << 16)
                | (static_cast<u64>(sha512tOutput[j + 4]) << 24)
                | (static_cast<u64>(sha512tOutput[j + 3]) << 32)
                | (static_cast<u64>(sha512tOutput[j + 2]) << 40)
                | (static_cast<u64>(sha512tOutput[j + 1]) << 48)
                | (static_cast<u64>(sha512tOutput[j + 0]) << 56);
        }
    }
    else
    {
        constexpr opType ivGeneratorXor = (generator512 && digestSize == 512) ? 0xa5a5a5a5a5a5a5a5 : 0;

        H[0] = static_cast<opType>(initialValues[ivIndex][0]) ^ ivGeneratorXor;
        H[1] = static_cast<opType>(initialValues[ivIndex][1]) ^ ivGeneratorXor;
        H[2] = static_cast<opType>(initialValues[ivIndex][2]) ^ ivGeneratorXor;
        H[3] = static_cast<opType>(initialValues[ivIndex][3]) ^ ivGeneratorXor;
        H[4] = static_cast<opType>(initialValues[ivIndex][4]) ^ ivGeneratorXor;
        H[5] = static_cast<opType>(initialValues[ivIndex][5]) ^ ivGeneratorXor;
        H[6] = static_cast<opType>(initialValues[ivIndex][6]) ^ ivGeneratorXor;
        H[7] = static_cast<opType>(initialValues[ivIndex][7]) ^ ivGeneratorXor;
    }
}

template<size_t digestSize, typename opType, bool generator512>
void crypto::SHA<digestSize, opType, generator512>::update(const u8* data, const size_t& size)
{
    constexpr size_t blockSize = width32 ? 64 : 128;

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

template<size_t digestSize, typename opType, bool generator512>
void crypto::SHA<digestSize, opType, generator512>::final(u8* data)
{
    constexpr size_t blockSize = width32 ? 64 : 128, blockStopSize = width32 ? 55 : 111;

    /*
    * I found the error function to be extremly prone to an implementation bug where the bytes
    * 56 to 63 in the last block won't change the digest. This is due to what I would guess
    * is a common misunderstandment of the specification, as in the case that these bytes exist
    * another block has to be added so the size data at the end doesn't overlap
    * with the last bytes. That would allow a space of 8 to 16 bytes for attcks, so I think this
    * implementation is the safest and also aligns with the results of the most common crypto
    * libraries used in real applications.
    */
    u64 blockPtr = (sumInputSize % blockSize);

    if (blockPtr <= blockStopSize)
    {
        block[blockPtr] = 0x80;
        memset(block + 1 + blockPtr, 0, blockSize - 9 - blockPtr);
    }
    else
    {
        block[blockPtr] = 0x80;
        memset(block + blockPtr + 1, 0, blockSize - blockPtr - 1);
        roundFunction(block);
        memset(block, 0, blockSize - 8);
    }

    size_t inputSizeBits = sumInputSize * 8;

    for (int i = (blockSize - 1), j = 0; i > blockStopSize; i--, j += 8)
    {
        if (j < 64)
        {
            block[i] = static_cast<u8>(inputSizeBits >> j);
        }
        else
        {
            block[i] = 0;
        }
    }

    roundFunction(block);

    for (int i = 0, j = 0; i < (digestSize / (sizeof(opType) * 8)); i++, j += sizeof(opType))
    {
        for (int k = 0; k < sizeof(opType); k++)
        {
            data[j + k] = (H[i] >> ((8 * sizeof(opType)) - (8 * (k + 1))) & 0xFF);
        }
    }

    init();
}

template<size_t digestSize, typename opType, bool generator512>
void crypto::SHA<digestSize, opType, generator512>::roundFunction(u8* data)
{
    constexpr size_t roundCount = width32 ? 64 : 80;

    opType a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    /*
    *                     32 bit word variant
    *
    * S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
    * S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
    *
    * s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
    * s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    *
    *
    *                     64 bit word variant
    *
    * S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
    * S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
    *
    * s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
    * s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
    *
    *
    * From these expressions we create lookup variables for the rotations and shifts.
    * Constant expression arrays behave weird in combination with lambdas so for this
    * to work out smoothly I have to create them by hand with the help of a macro.
    * Each macro is of the format:
    * V_W where v describes in which formula the constant goes and w at which point in that
    * formula. Every function of these does 3 shifts or rotations, so each formula needs
    * 3 constants. This I use numbers from 0 to 2 inclusive to describe at which point
    * the constant goes.
    *
    *                        Macro variant
    *
    * S0 := (a rightrotate S0_0) xor (a rightrotate S0_1) xor (a rightrotate S0_2)
    * S1 := (e rightrotate S1_0) xor (e rightrotate S1_1) xor (e rightrotate S1_2)
    *
    * s0 := (w[i-15] rightrotate s0_0) xor (w[i-15] rightrotate s0_1) xor (w[i-15] rightshift s0_2)
    * s1 := (w[i-2] rightrotate s1_0) xor (w[i-2] rightrotate s1_1) xor (w[i-2] rightshift s1_2)
    */

#define V(x, n32, n64) constexpr int x = width32 ? n32 : n64;

    V(S0_0, 2, 28);
    V(S0_1, 13, 34);
    V(S0_2, 22, 39);

    V(S1_0, 6, 14);
    V(S1_1, 11, 18);
    V(S1_2, 25, 41);

    V(s0_0, 7, 1);
    V(s0_1, 18, 8);
    V(s0_2, 3, 7);

    V(s1_0, 17, 19);
    V(s1_1, 19, 61);
    V(s1_2, 10, 6);

#undef V

    opType w[roundCount];

    /*
    * Reading the input data as big endian.
    * The message can now be read as an array of 32-bit or 64-bit words which are now to be expanded.
    * This might be optimized by hardcording the readin and hiding the expanding behind a constexpr,
    * as there are really only two cases: sizeof(t) == 4 and sizeof(t) == 8.
    */

    for (int i = 0; i < 16; i++)
    {
        w[i] = 0;
        for (int j = 0; j < sizeof(opType); j++)
        {
            w[i] |= static_cast<opType>(data[(i * sizeof(opType)) + j]) << ((sizeof(opType) - (j + 1)) * 8);
        }
    }

    /*
    * In this step the message is being expanded from 16 32-bit words to 64 32-bit words
    * in SHA-224 and SHA-256. In every other sha2 function the message is being expanded
    * from 16 64-bit words to 80 64-bit words.
    * An expanded word (word 16 to word 64/80, w[16] .. w[64/80]) is the sum of the words
    * indexed 16 and 7 entries before as well as the words indexed 15 and 2 words before
    * but shifted and rotated.
    * That process visualised looks something like this for the first 64 characters of
    * "lorem impsum" as input:
    *
    *
    * w0  01001100011011110111001001100101 |->ror( w1, 7):  11100000110110100100000011010010 ^
    * w1  01101101001000000110100101110000-|->ror( w1,18):  00011010010111000001101101001000 ^
    * w2  01110011011101010110110100100000 |->shr( w1, 3):  00001101101001000000110100101110
    * w3  01100100011011110110110001101111                = 11110111001000100101011010110100----|
    * w4  01110010001000000111001101101001                                                      |
    * w5  01110100001000000110000101101101 |->ror(w14,17):  10110010101100100001000000111001 ^  |
    * w6  01100101011101000010110000100000 |->ror(w14,19):  01101100101011001000010000001110 ^  |
    * w7  01100011011011110110111001110011 |->shr(w14,10):  00000000000010000001110011011001    |
    * w8  01100101011101000110010101110100 |              = 11011110000101101000100011101110--| |
    * w9  01110101011100100010000001110011 |                                                  | |
    * w10 01100001011001000110100101110000 |                11011110000101101000100011101110<-| |
    * w11 01110011011000110110100101101110 |              + 11110111001000100101011010110100<---|
    * w12 01100111001000000110010101101100 |              + 01001100011011110111001001100101 : w0
    * w13 01101001011101000111001000101100 |              + 01110101011100100010000001110011 : w9
    * w14 00100000011100110110010101100100-|              = 10010111000110100111001001111010--|
    * w15 00100000011001000110100101100001                                                    |
    * w16 10010111000110100111001001111010 <--------------------------------------------------|
    */

    for (size_t i = 16; i < roundCount; i++)
    {
        opType s0 = crotr<s0_0, opType>(w[i - 15]) ^ crotr<s0_1, opType>(w[i - 15]) ^ (w[i - 15] >> (s0_2));
        opType s1 = crotr<s1_0, opType>(w[i - 2]) ^ crotr<s1_1, opType>(w[i - 2]) ^ (w[i - 2] >> (s1_2));
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    for (size_t i = 0; i < roundCount; i++)
    {
        const opType S1 = crotr<S1_0, opType>(e) ^ crotr<S1_1, opType>(e) ^ crotr<S1_2, opType>(e);
        const opType ch = (e & f) ^ ((~e) & g);
        const opType temp1 = h + S1 + ch + static_cast<opType>(width32 ? k32[i] : k64[i]) + w[i];
        const opType S0 = crotr<S0_0, opType>(a) ^ crotr<S0_1, opType>(a) ^ crotr<S0_2, opType>(a);
        const opType maj = (a & b) ^ (a & c) ^ (b & c);
        const opType temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    /*
    * Last step of the SHA-2 round function: add the intermediate values to the digest.
    * This might be optimized as it's a fairly linear operation that could be merged
    * into the other function steps.
    */

    H[0] = H[0] + a;
    H[1] = H[1] + b;
    H[2] = H[2] + c;
    H[3] = H[3] + d;
    H[4] = H[4] + e;
    H[5] = H[5] + f;
    H[6] = H[6] + g;
    H[7] = H[7] + h;
}

template class crypto::SHA<224, sha2::state256>;
template class crypto::SHA<256, sha2::state256>;
template class crypto::SHA<384, sha2::state512>;
template class crypto::SHA<512, sha2::state512>;

#ifdef NO_SHA_512T

template class crypto::SHA<384, state512>;
template class crypto::SHA<512, state512>;

template class crypto::SHA<224, state512>;
template class crypto::SHA<256, state512>;

#else

#define LS(x) template class crypto::SHA<x, sha2::state512>
#define LS32(x) LS(x + 8); LS(x + 16); LS(x + 24); LS(x + 32)
#define LS128(y) LS32(y); LS32(y + 32); LS32(y + 64); LS32(y + 96);

LS128(0); LS128(128); LS128(256); LS128(384);



#endif