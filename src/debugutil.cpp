#include "debugutil.h"

std::ostream& operator<<(std::ostream& o, const crypto::u8& data)
{
	o << "0123456789abcdef"[(data >> 4) & 0xf] << "0123456789abcdef"[data & 0xf];
	return o;
}
