#pragma once
#include <windows.h>
#include <string>
#include <iostream>

extern DWORD crc_32_tab[];

static inline DWORD updateCRC32(unsigned char ch, DWORD crc)
{
    return crc_32_tab[(crc ^ ch) & 0xff] ^ (crc >> 8);
}

bool crc32file(char* name, DWORD& outCrc);

DWORD GetImageCrc32();

const std::wstring& GetGamePath();