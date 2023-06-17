#pragma once

#include "hashbase.h"

#include <iostream>
#include <Windows.h>

std::ostream& operator<< (std::ostream& o, const crypto::u8& data);

inline void ConsoleColor(int color)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color);
}