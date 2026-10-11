#include "PlainPsarc.h"
#include <cstdint>
#include <cstring>
#include <iostream>
#include <windows.h>
#include "MemUtil.h"
#include "VirtualMemory.h"

// PSARC header archiveFlags: bit 0x4 marks an encrypted TOC. Every stock archive sets it, but the
// game decrypts the TOC unconditionally - so a plain TOC turns into garbage and the game crashes.
//
// SNG header: u32 magic 0x4A, u32 flags. Stock charts use flags 3 (compressed + encrypted) and the
// game rejects anything else. Plain charts use flags 1 (compressed only) with the same layout:
//   magic | flags | 16-byte IV slot (unused) | u32 uncompressed size | zlib data | 56-byte signature

static const uint32_t SNG_MAGIC = 0x4A;
static const uint32_t SNG_FLAGS_PLAIN = 1;

static uintptr_t tocDecryptReturn; // original decrypt path, after the instructions we overwrote
static uintptr_t tocSkipTarget;    // first instruction after the TOC decrypt block
static uintptr_t sngFlagsAccepted;
static uintptr_t sngFlagsRejected;

typedef bool(__cdecl* tSngDecrypt)(const uint8_t* src, uint32_t len, const char* key, uint32_t keyLen, uint8_t* out, uint32_t outLen);
static tSngDecrypt oSngDecrypt;

// Replaces mov ecx,10h at the start of the TOC decrypt block (mov eax,[ebp-74h] before it still runs).
void __declspec(naked) hook_TocDecrypt() {
	__asm {
		test byte ptr[ebp - 0x54], 4 // archiveFlags
		jz plain

		mov ecx, 0x10
		jmp dword ptr[tocDecryptReturn]

	plain:
		mov edx, dword ptr[ebp - 0x74]
		mov edi, dword ptr[edx]
		jmp dword ptr[tocSkipTarget]
	}
}

void __declspec(naked) hook_SngFlags() {
	__asm {
		cmp dword ptr[esp + 0x68], 3
		je accepted
		cmp dword ptr[esp + 0x68], 1 // SNG_FLAGS_PLAIN
		je accepted
		jmp dword ptr[sngFlagsRejected]

	accepted:
		jmp dword ptr[sngFlagsAccepted]
	}
}

// Called in place of the game's SNG decrypt. src points just past the 8-byte header of the
// in-memory SNG and starts with the IV; the game expects the plaintext payload at out[0].
static bool __cdecl SngDecryptOrCopy(const uint8_t* src, uint32_t len, const char* key, uint32_t keyLen, uint8_t* out, uint32_t outLen) {
	const uint32_t magic = *(const uint32_t*)(src - 8);
	const uint32_t flags = *(const uint32_t*)(src - 4);

	if (magic != SNG_MAGIC || flags != SNG_FLAGS_PLAIN)
		return oSngDecrypt(src, len, key, keyLen, out, outLen);

	if (len < 0x10 || outLen < len - 0x10)
		return false;

	memcpy(out, src + 0x10, len - 0x10);
	return true;
}

static uint8_t* FindInText(const char* sig, const char* mask) {
	return MemUtil.FindPattern(VirtualMemory.GetTextSectionAddress(), VirtualMemory.GetTextSectionLength(), (uint8_t*)sig, (char*)mask);
}

// The game reads PSARC TOCs while starting up, possibly while we patch. Replace the single 5-byte
// instruction at jmpSite with a jmp in one atomic exchange of the aligned qword holding it, so a
// thread running this code sees either the old or the new instruction, never a half-written one.
static bool PlaceJmpAtomic(uint8_t* jmpSite, void* target) {
	uint64_t* qword = (uint64_t*)((uintptr_t)jmpSite & ~(uintptr_t)7);
	const size_t offset = jmpSite - (uint8_t*)qword;
	if (offset + 5 > sizeof(uint64_t))
		return false;

	const uint64_t oldCode = *qword;
	uint64_t newCode = oldCode;
	uint8_t* bytes = (uint8_t*)&newCode;
	bytes[offset] = 0xE9;
	*(int32_t*)(bytes + offset + 1) = (int32_t)((uintptr_t)target - ((uintptr_t)jmpSite + 5));

	DWORD oldProtect, dummy;
	if (!NT_SUCCESS(VirtualMemory.RedirectedProtectVirtualMemory(qword, sizeof(uint64_t), PAGE_EXECUTE_READWRITE, &oldProtect)))
		return false;

	const bool swapped = InterlockedCompareExchange64((volatile LONG64*)qword, (LONG64)newCode, (LONG64)oldCode) == (LONG64)oldCode;

	VirtualMemory.RedirectedProtectVirtualMemory(qword, sizeof(uint64_t), oldProtect, &dummy);
	FlushInstructionCache(GetCurrentProcess(), qword, sizeof(uint64_t));
	return swapped;
}

bool PatchPlainPsarc() {
	// mov eax,[ebp-74h] / mov ecx,10h / mov esi,<toc key> / lea edi,[ebp-50h] / rep movsd / movsb
	uint8_t* tocSite = FindInText("\x8B\x45\x8C\xB9\x10\x00\x00\x00\xBE\x00\x00\x00\x00\x8D\x7D\xB0\xF3\xA5\xA4", "xxxxxxxxx????xxxxxx");
	// cmp dword ptr [esp+68h],3 / jne fail / call <verify signature> / test al,al / je
	uint8_t* sngFlagsSite = FindInText("\x83\x7C\x24\x68\x03\x0F\x85\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x84\xC0\x0F\x84", "xxxxxxx????x????xxxx");
	// mov byte ptr [esp+7Dh],1 / call <sng decrypt> / add esp,18h / test al,al / jne
	uint8_t* sngDecryptSite = FindInText("\xC6\x44\x24\x7D\x01\xE8\x00\x00\x00\x00\x83\xC4\x18\x84\xC0\x75", "xxxxxx????xxxxxx");

	// mov edx,[ebp-74h] / mov edi,[edx] / add esp,28h - the end of the TOC decrypt block
	if (tocSite && memcmp(tocSite + 0x48, "\x8B\x55\x8C\x8B\x3A\x83\xC4\x28", 8) != 0) {
		std::cerr << "Plain PSARC: unexpected code after the TOC decrypt block." << std::endl;
		tocSite = nullptr;
	}

	if (!tocSite || !sngFlagsSite || !sngDecryptSite) {
		std::cerr << "Plain PSARC: pattern not found (TOC " << (void*)tocSite << ", SNG flags " << (void*)sngFlagsSite
			<< ", SNG decrypt " << (void*)sngDecryptSite << "). Unencrypted CDLC will not load." << std::endl;
		return false;
	}

	tocDecryptReturn = (uintptr_t)tocSite + 8;
	tocSkipTarget = (uintptr_t)tocSite + 0x50;

	sngFlagsAccepted = (uintptr_t)sngFlagsSite + 0xB;
	sngFlagsRejected = sngFlagsAccepted + *(int32_t*)(sngFlagsSite + 7);

	uint8_t* sngDecryptCall = sngDecryptSite + 5;
	oSngDecrypt = (tSngDecrypt)(sngDecryptCall + 5 + *(int32_t*)(sngDecryptCall + 1));

	uint8_t callPatch[5] = { 0xE8 };
	*(int32_t*)(callPatch + 1) = (int32_t)((uintptr_t)&SngDecryptOrCopy - ((uintptr_t)sngDecryptCall + 5));

	if (!PlaceJmpAtomic(tocSite + 3, (void*)hook_TocDecrypt)
		|| !MemUtil.PlaceHook(sngFlagsSite, (void*)hook_SngFlags, 0xB)
		|| !MemUtil.PatchAdr(sngDecryptCall, callPatch, sizeof(callPatch))) {
		std::cerr << "Plain PSARC: failed to patch." << std::endl;
		return false;
	}

	std::cout << "Plain PSARC: unencrypted TOC and SNG support enabled." << std::endl;
	return true;
}
