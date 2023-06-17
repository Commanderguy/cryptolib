#pragma once

#include "hashbase.h"

namespace crypto
{
	namespace keccakParams
	{
		typedef u8 b200;
		typedef u16 b400;
		typedef u32 b800;
		typedef u64 b1600;
	}

	template<typename blockSizeParamL = keccakParams::b1600>
	void keccakPermutation(u8* state);

	inline void keccakf1600(u8* state) { return keccakPermutation<keccakParams::b1600>(state); };
	inline void  keccakf800(u8* state) { return keccakPermutation< keccakParams::b800>(state); };
	inline void  keccakf400(u8* state) { return keccakPermutation< keccakParams::b400>(state); };
	inline void  keccakf200(u8* state) { return keccakPermutation< keccakParams::b200>(state); };
}