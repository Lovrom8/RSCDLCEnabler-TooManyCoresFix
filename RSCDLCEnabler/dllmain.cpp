#include "d3dx9_42.h"
#include <fstream>
#include <iostream>
#include <thread>
#include <windows.h> 
#include "MemUtil.h"
#include "DualLogger.h"
#include "MemoryHelpers.h"

std::ofstream logFile;

void InitializeLogging() {
	logFile.open("log.txt", std::ios::out | std::ios::app);
	if (!logFile) {
		std::cerr << "Failed to open log file." << std::endl;
		return;
	}

	static DualLogger dualCoutBuf(std::cout.rdbuf(), logFile);
	static DualLogger dualCerrBuf(std::cerr.rdbuf(), logFile);

	std::cout.rdbuf(&dualCoutBuf);
	std::cerr.rdbuf(&dualCerrBuf);
}

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

	InitializeLogging();
	std::cout << "Logging Initialized. Writing to console and file." << std::endl;
}

void LetMePlayCDLCEvenThoughIDontHaveCherubRock(uint32_t BaseTextAddress) {
	uint8_t* AppIdCheckOffset = MemUtil.FindPattern(BaseTextAddress, GetTextSectionLength(), (uint8_t*)"\x8B\x90\x00\x00\x00\x00\x56\xFF\xD2\x84\xC0\x75\x38", "xx????xxxxxxx"); // 0x008CA6FC | same instructions, wrong place - 0x00EE9D5C 

	AppIdCheckOffset += 0xB;
	std::cout << "Pattern found at offset: " << std::hex << (void*)AppIdCheckOffset << std::endl;

	if (AppIdCheckOffset) {
		CheckMemoryProtection((void*)AppIdCheckOffset);

		if (*(byte*)AppIdCheckOffset != 0x75) {
			std::cout << "Found unexpected byte at offset. Expected 0x75, got " << std::hex << (int)*(byte*)AppIdCheckOffset << std::endl;
		}
		else {
			std::cout << "Expected byte found." << std::endl;
		}

		if (MemUtil.PatchAdr((char*)AppIdCheckOffset, "\xEB", 1)) {
			std::cout << "App ID check patched." << std::endl;
		}
		else {
			std::cerr << "Failed to patch app ID check." << std::endl;
		}
	}
	else {
		std::cerr << "Pattern not found!" << std::endl;
	}
}

void vmp_virtualprotect_check_disable()
{
	DWORD old_protect = 0;
	auto ntdll = GetModuleHandleA("ntdll.dll");

	BYTE callcode = ((BYTE*)GetProcAddress(ntdll, "NtQuerySection"))[1] - 1;
	BYTE restore[] = { 0xB8, callcode, 0x00, 0x00, 0x00 };

	auto nt_vp = (BYTE*)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	VirtualProtect(nt_vp, sizeof(restore), PAGE_EXECUTE_READWRITE, &old_protect);
	memcpy(nt_vp, restore, sizeof(restore));
	VirtualProtect(nt_vp, sizeof(restore), old_protect, &old_protect);
}

DWORD WINAPI MainThread(void*) {
	std::cout << "MainThread started." << std::endl;
	vmp_virtualprotect_check_disable();

	uint8_t* VerifySignatureOffset = nullptr;

	uint32_t BaseTextAddress = GetTextSectionAddress();

	if (BaseTextAddress == 0) {
		std::cerr << "Failed to get the base address of the .text section." << std::endl;
		return 0;
	}

	while (!GetModuleHandleA("d3d9.dll")) {
		std::cout << "Waiting for d3d9.dll..." << std::endl;
		Sleep(1000);
	}

	VerifySignatureOffset = MemUtil.FindPattern(BaseTextAddress, GetTextSectionLength(), (uint8_t*)"\x8B\x45\xFC\x2B\xD8\x03\x45\xF8\x56\x53\x50", "xxxxxxxxxxx");
	if (VerifySignatureOffset) {
		VerifySignatureOffset += 0x13;
		CheckMemoryProtection((void*)VerifySignatureOffset);

		std::cout << "Pattern found at offset: " << std::hex << (void*)VerifySignatureOffset << std::endl;

		if (*(byte*)VerifySignatureOffset != 0x8A && *(byte*)(VerifySignatureOffset + 0x1) == 0xD8) {
			std::cout << "Found unexpected byte at offset. Expected 0x8A, got " << std::hex << (int)*(byte*)VerifySignatureOffset << std::endl;
			std::cout << "Found unexpected byte at offset+1. Expected 0xD8, got " << std::hex << (int)*(byte*)(VerifySignatureOffset + 0x1) << std::endl;
			return 0;
		}
		else {
			std::cout << "Expected byte found." << std::endl;
		}

		std::cout << "Patching signature verification..." << std::endl;
		if (MemUtil.PatchAdr((char*)VerifySignatureOffset, "\xB3\x01", 2)) {
			std::cout << "Signature verification patched." << std::endl;
			std::cout << "--------" << std::endl;

			LetMePlayCDLCEvenThoughIDontHaveCherubRock(BaseTextAddress);
		}
		else {
			std::cerr << "Failed to patch signature verification." << std::endl;
		}
	}
	else {
		std::cerr << "Pattern not found!" << std::endl;
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
