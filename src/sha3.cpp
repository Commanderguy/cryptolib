#include "sha3.h"

#include "keccak.h"

#include "debugutil.h"

#include <cstring>

using namespace crypto;

template<size_t digestSize>
crypto::SHA3<digestSize>::SHA3()
{
    init();
}

template<size_t digestSize>
inline void crypto::SHA3<digestSize>::operator()(const u8* message, const size_t& size, u8* digest)
{
    init();
    update(message, size);
    final(digest);
}

template<size_t digestSize>
inline void crypto::SHA3<digestSize>::init()
{
    memset(state, 0, bBytes);
    sumInputSize = 0;
}

template<size_t digestSize>
inline void crypto::SHA3<digestSize>::update(const u8* data, const size_t& size)
{
    size_t statePtr = sumInputSize % rBytes;
    size_t bytesNeeded = rBytes - statePtr;
    size_t mutSize = size;

    if (bytesNeeded > size)
    {
        for (int i = 0; i < size; i++)
        {
            state[statePtr + i] ^= data[i];
        }
        sumInputSize += size;
        return;
    }

    while (mutSize != 0)
    {
        state[statePtr] ^= data[size - mutSize];
        statePtr++;
        mutSize--;
        if (statePtr == rBytes)
        {
            keccakf1600(state);
            statePtr = 0;
        }
    }

    sumInputSize += size;
}

template<size_t digestSize>
inline void crypto::SHA3<digestSize>::final(u8* data)
{
    size_t statePtr = sumInputSize % rBytes;

    state[statePtr] ^= 0x06;
    state[rBytes - 1] ^= 0x80;

    keccakf1600(state);

    for (size_t i = 0; i < (digestSizeBytes); i++)
    {
        data[i] = state[i];
    }
}

template class crypto::SHA3<224>;
template class crypto::SHA3<256>;
template class crypto::SHA3<384>;
template class crypto::SHA3<512>;