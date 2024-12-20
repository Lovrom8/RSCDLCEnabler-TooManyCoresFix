#include "d3dx9_42.h"
#include <fstream>
#include <iostream>
#include <thread>
#include <windows.h> 
#include "MemUtil.h"

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
}

void LetMePlayCDLCEvenThoughIDontHaveCherubRock() {
    uint8_t* AppIdCheckOffset = MemUtil.FindPattern(0x401000, 0x4CC603C, (uint8_t*)"\x8B\x90\x00\x00\x00\x00\x56\xFF\xD2\x84\xC0\x75\x38\x81", "xx????xxxxxxxx"); // 0x008CA6FC | same instructions, wrong place - 0x00EE9D5C 

    if (AppIdCheckOffset) {
        AppIdCheckOffset += 0xB;
		std::cout << "Patching app ID check... " << std::endl;
		std::cout << "Pattern found at offset: " << std::hex << (void*)AppIdCheckOffset << std::endl;
		MemUtil.PatchAdr((char*)AppIdCheckOffset, "\xEB", 1);
	}
	else {
		std::cerr << "Pattern not found!" << std::endl;
	}
}

DWORD WINAPI MainThread(void*) {
    uint8_t* VerifySignatureOffset = nullptr;

    std::cout << "MainThread started." << std::endl;

    while (!GetModuleHandleA("d3d9.dll")) {
        std::cout << "Waiting for d3d9.dll..." << std::endl;
        Sleep(500);
    }

    VerifySignatureOffset = MemUtil.FindPattern(0x401000, 0x4CC603C, (uint8_t*)"\x8A\xD8\x85\xF6\x74\x00\x80\x3D", "xxxxx?xx"); // 0x0055834A | same instructions, wrong place -  0x00B796FA 
    if (VerifySignatureOffset) {
        std::cout << "Patching signature verification... " << std::endl;
        std::cout << "Pattern found at offset: " << std::hex << (void*)VerifySignatureOffset << std::endl;
        MemUtil.PatchAdr((char*)VerifySignatureOffset, "\xB3\x01", 2);
        LetMePlayCDLCEvenThoughIDontHaveCherubRock();
    }
    else {
        std::cerr << "Pattern not found!" << std::endl;
    }

    return 0;
}

void Initialize(void) {
    CreateConsole(); // Initialize the console
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
