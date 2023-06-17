#include "keccak.h"

namespace crypto
{
    constexpr u64 RC[24] = { 0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,
                                0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,
                                0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,
                                0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,
                                0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,
                                0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008 };
}

template<typename blockSizeParamL>
void crypto::keccakPermutation(u8* state)
{
    size_t roundCount = 24;
    switch (sizeof(blockSizeParamL))
    {
        case sizeof( u8) : roundCount = 18; break;
        case sizeof(u16) : roundCount = 20; break;
        case sizeof(u32) : roundCount = 22; break;
        case sizeof(u64) : roundCount = 24; break;
    }

    typedef blockSizeParamL stateType;
    stateType* A = reinterpret_cast<stateType*>(state);
    const auto lane = [&A](size_t x, size_t y) -> stateType& {return A[x + (5 * y)]; };
    stateType C[5];

    for (int r = 0; r < roundCount; r++)
    {
        // Theta
        for (int k = 0; k < 5; k++)
        {
            C[k] = lane(k, 0) ^ lane(k, 1) ^ lane(k, 2) ^ lane(k, 3) ^ lane(k, 4);
        }

        for (int k = 0; k < 5; k++)
        {
            lane(0, k) = lane(0, k) ^ (C[4] ^ crotl<1, stateType>(C[1]));
            lane(1, k) = lane(1, k) ^ (C[0] ^ crotl<1, stateType>(C[2]));
            lane(2, k) = lane(2, k) ^ (C[1] ^ crotl<1, stateType>(C[3]));
            lane(3, k) = lane(3, k) ^ (C[2] ^ crotl<1, stateType>(C[4]));
            lane(4, k) = lane(4, k) ^ (C[3] ^ crotl<1, stateType>(C[0]));
        }

        // Rho and Pi put together

        /*
        *   Script:

            int x = 1, y = 0, tmp, table[5][5];
            for (int t = 0; t < 24; t++)
            {
                table[x][y] = ((t + 1) * (t + 2) / 2);
                tmp = x;
                x = y;
                y = ((2 * tmp) + (3 * y)) % 5;
            }
            x = 0, y = 1;
            int tx;
            do
            {
                tx = (x + (3 * y)) % 5;
                std::cout << "lane(" << x << "," << y << ") = crotl<" << (table[tx][x]) << ", stateType>(lane(" << tx << ", " << x << ")); " << std::endl;
                y = x;
                x = tx;
            } while (!(x == 0 && y == 1));
        */

        C[0] = lane(0, 1);
        lane(0, 1) = crotl< 28, stateType>(lane(3, 0));
        lane(3, 0) = crotl< 21, stateType>(lane(3, 3));
        lane(3, 3) = crotl< 15, stateType>(lane(2, 3));
        lane(2, 3) = crotl< 10, stateType>(lane(1, 2));
        lane(1, 2) = crotl<  6, stateType>(lane(2, 1));
        lane(2, 1) = crotl<  3, stateType>(lane(0, 2));
        lane(0, 2) = crotl<  1, stateType>(lane(1, 0));
        lane(1, 0) = crotl<300, stateType>(lane(1, 1));
        lane(1, 1) = crotl<276, stateType>(lane(4, 1));
        lane(4, 1) = crotl<253, stateType>(lane(2, 4));
        lane(2, 4) = crotl<231, stateType>(lane(4, 2));
        lane(4, 2) = crotl<210, stateType>(lane(0, 4));
        lane(0, 4) = crotl<190, stateType>(lane(2, 0));
        lane(2, 0) = crotl<171, stateType>(lane(2, 2));
        lane(2, 2) = crotl<153, stateType>(lane(3, 2));
        lane(3, 2) = crotl<136, stateType>(lane(4, 3));
        lane(4, 3) = crotl<120, stateType>(lane(3, 4));
        lane(3, 4) = crotl<105, stateType>(lane(0, 3));
        lane(0, 3) = crotl< 91, stateType>(lane(4, 0));
        lane(4, 0) = crotl< 78, stateType>(lane(4, 4));
        lane(4, 4) = crotl< 66, stateType>(lane(1, 4));
        lane(1, 4) = crotl< 55, stateType>(lane(3, 1));
        lane(3, 1) = crotl< 45, stateType>(lane(1, 3));
        lane(1, 3) = crotl< 36, stateType>(C[0]);

        // Chi
        for (int i = 0; i < 5; i++)
        {
            C[0] = lane(0, i);
            C[1] = lane(1, i);
            C[2] = lane(2, i);
            C[3] = lane(3, i);
            C[4] = lane(4, i);

            lane(0, i) ^= ~(C[1]) & C[2];
            lane(1, i) ^= ~(C[2]) & C[3];
            lane(2, i) ^= ~(C[3]) & C[4];
            lane(3, i) ^= ~(C[4]) & C[0];
            lane(4, i) ^= ~(C[0]) & C[1];
        }

        // Iota
        lane(0, 0) = lane(0, 0) ^ static_cast<stateType>(RC[r]);
    }
}

template void crypto::keccakPermutation<crypto::keccakParams::b1600>(u8* state);
template void crypto::keccakPermutation<crypto::keccakParams::b800>(u8* state);
template void crypto::keccakPermutation<crypto::keccakParams::b400>(u8* state);
template void crypto::keccakPermutation<crypto::keccakParams::b200>(u8* state);