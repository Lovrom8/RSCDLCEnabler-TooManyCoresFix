#include "d3dx9_42.h"
#include <fstream>
#include <iostream>
#include <thread>
#include "MemUtil.h"

void LetMePlayCDLCEvenThoughIDontHaveCherubRock() {
	MemUtil.PatchAdr((char*)0x008CA6FC, "\xEB", 1);
}

DWORD WINAPI MainThread(void*) {
	uint8_t* VerifySignatureOffset = nullptr;

	try
	{
		VerifySignatureOffset = MemUtil.FindPattern(0x01377000, 0x00DDE000, (uint8_t*)"\xE8\x00\x00\x00\x00\x83\xC4\x20\x88\xC3", "x????xxxxx");
	}
	catch (...) {}

	if (VerifySignatureOffset == nullptr) {
		while (!GetModuleHandleA("d3d9.dll"))
			Sleep(500);

		VerifySignatureOffset = MemUtil.FindPattern(0x00557000, 0x00DDE000, (uint8_t*)"\xE8\x00\x00\x00\x00\x83\xC4\x20\x8A\xD8", "x????xxxxx");
	}

	if (VerifySignatureOffset) {
		MemUtil.PatchAdr(VerifySignatureOffset + 8, "\xB3\x01", 2);
		LetMePlayCDLCEvenThoughIDontHaveCherubRock();
	}

	return 0;
}

void Initialize(void) {
	CreateThread(NULL, 0, MainThread, NULL, NULL, 0);
}

void SetBitmask() {
	DWORD_PTR bitmask = 0x7FFFFFFF; // 7FFFFFFF = 1111111111111111111111111111111 in binary, so 31 one's -> 31 max 
	unsigned long coreCount = std::thread::hardware_concurrency();

	if (coreCount >= 31)
		SetProcessAffinityMask(GetCurrentProcess(), bitmask);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		SetBitmask();
		Initialize();
		InitProxy();
		return TRUE;
	case DLL_PROCESS_DETACH:
		ShutdownProxy();
		return TRUE;
	}
	return TRUE;
}
