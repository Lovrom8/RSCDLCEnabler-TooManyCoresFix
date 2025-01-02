#include "d3dx9_42.h"
#include <fstream>
#include <iostream>
#include <thread>
#include <windows.h> 
#include "MemUtil.h"
#include "DualLogger.h"
#include "VirtualMemory.h"
#include "Util.h"
#include "WinUser.h"

void CreateConsole() {
	AllocConsole();
	FILE* file;
	freopen_s(&file, "CONOUT$", "w", stdout);
	freopen_s(&file, "CONOUT$", "w", stderr);
	freopen_s(&file, "CONIN$", "r", stdin);
	std::cout.clear();
	std::cerr.clear();
	std::cin.clear();
	std::cout << "Console Initialized." << std::endl;

	cDualLogger::InitializeLogging();
	std::cout << "Logging Initialized. Writing to console and file." << std::endl;
}

void LetMePlayCDLCEvenThoughIDontHaveCherubRock(uint32_t BaseTextAddress) {
	uint8_t* AppIdCheckOffset = MemUtil.FindPattern(BaseTextAddress, VirtualMemory.GetTextSectionLength(), (uint8_t*)"\x8B\x90\x00\x00\x00\x00\x56\xFF\xD2\x84\xC0\x75\x38", "xx????xxxxxxx"); // 0x008CA6FC | same instructions, wrong place - 0x00EE9D5C 

	if (AppIdCheckOffset) {
		AppIdCheckOffset += 0xB;
		std::cout << "Pattern found at offset: " << std::hex << (void*)AppIdCheckOffset << std::endl;

		if (*(byte*)AppIdCheckOffset != 0x75) {
			std::cout << "Found unexpected byte at offset. Expected 0x75, got " << std::hex << (int)*(byte*)AppIdCheckOffset << std::endl;
		}
		else {
			std::cout << "Expected byte found." << std::endl;
		}

		if (MemUtil.PatchAdr((char*)AppIdCheckOffset, "\xEB", 1)) {
			if (*(byte*)AppIdCheckOffset == 0xEB)
			{
				std::cout << "App ID check patched." << std::endl;
			}
			else {
				std::cerr << "Failed to patch App ID check." << std::endl;
				std::cout << "Found unexpected byte at offset. Expected 0xEB, got " << std::hex << (int)*(byte*)AppIdCheckOffset << std::endl;
			}
		}
		else {
			std::cerr << "Failed to patch app ID check." << std::endl;
			MessageBoxW(NULL, L"Could not find the correct memory location for the API ID check!", L"Error", MB_ICONERROR);
		}

		std::cout << "--------" << std::endl;
	}
	else {
		std::cerr << "Pattern not found!" << std::endl;
	}
}

void PatchSongKeyLookupTable() {
	uint32_t BaseTextAddress = VirtualMemory.GetTextSectionAddress();

	const char* sig = "\x74\x00\x83\xC1\x00\x81\xF9\x00\x00\x00\x00\x72";
	char* mask = "x?xx?xx????x";

	DWORD patchAdr = (DWORD)MemUtil.FindPattern(BaseTextAddress, VirtualMemory.GetTextSectionLength(), (uint8_t*)sig, mask);
	if (MemUtil.PatchAdr((char*)patchAdr, "\xEB", 1)) {
		std::cout << "Patched song key lookup successfully!" << std::endl;
	}
	else {
		std::cerr << "Failed to patch!" << std::endl;
		MessageBoxW(NULL, L"Could not find the correct memory location for the DLC lookup table!", L"Error", MB_ICONERROR);
	}
}

bool IsLPVersion() {
	const DWORD imageCRC = GetImageCrc32();

	return imageCRC == 0x6EA6d1BA;
}

DWORD WINAPI MainThread(void*) {
	std::cout << "MainThread started." << std::endl;

	VirtualMemory.IsLPVersion = IsLPVersion();
	VirtualMemory.InitMemoryManagement();

	uint8_t* VerifySignatureOffset = nullptr;

	uint32_t BaseTextAddress = VirtualMemory.GetTextSectionAddress();

	if (BaseTextAddress == 0) {
		std::cerr << "Failed to get the base address of the .text section." << std::endl;
		return 0;
	}
	else {
		std::cout << "Base address of .text section at: " << std::hex << (void*)BaseTextAddress << std::endl;
	}

	while (!GetModuleHandleA("d3d9.dll")) {
		std::cout << "Waiting for d3d9.dll..." << std::endl;
		Sleep(1000);
	}

	VerifySignatureOffset = MemUtil.FindPattern(BaseTextAddress, VirtualMemory.GetTextSectionLength(), (uint8_t*)"\x8B\x45\xFC\x2B\xD8\x03\x45\xF8\x56\x53\x50", "xxxxxxxxxxx");
	if (VerifySignatureOffset) {
		VerifySignatureOffset += 0x13;

		std::cout << "Pattern found at offset: " << std::hex << (void*)VerifySignatureOffset << std::endl;

		if (*(byte*)VerifySignatureOffset != 0x8A || *(byte*)(VerifySignatureOffset + 0x1) != 0xD8) {
			std::cout << "Found unexpected byte at offset. Expected 0x8A, got " << std::hex << (int)*(byte*)VerifySignatureOffset << std::endl;
			std::cout << "Found unexpected byte at offset+1. Expected 0xD8, got " << std::hex << (int)*(byte*)(VerifySignatureOffset + 0x1) << std::endl;
			return 0;
		}
		else {
			std::cout << "Expected byte found." << std::endl;
		}

		std::cout << "Patching signature verification..." << std::endl;

		if (MemUtil.PatchAdr((char*)VerifySignatureOffset, "\xB3\x01", 2)) {
			if (*(byte*)VerifySignatureOffset == 0xB3 && *(byte*)(VerifySignatureOffset + 0x1) == 0x01)
			{
				std::cout << "Patched successfully!" << std::endl;
				LetMePlayCDLCEvenThoughIDontHaveCherubRock(BaseTextAddress);

				if (VirtualMemory.IsLPVersion)
					PatchSongKeyLookupTable();
			}
			else {
				std::cerr << "Failed to patch signature verification." << std::endl;
				std::cout << "Found unexpected byte at offset. Expected 0xB3, got " << std::hex << (int)*(byte*)VerifySignatureOffset << std::endl;
				std::cout << "Found unexpected byte at offset+1. Expected 0x01, got " << std::hex << (int)*(byte*)(VerifySignatureOffset + 0x1) << std::endl;
			}

			std::cout << "--------" << std::endl;
		}
	}
	else {
		std::cerr << "Pattern not found!" << std::endl;
		MessageBoxW(NULL, L"Could not find the correct memory location for the DLC signature patch!", L"Error", MB_ICONERROR);
	}

	return 0;
}

void Initialize(void) {
	CreateConsole();
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
