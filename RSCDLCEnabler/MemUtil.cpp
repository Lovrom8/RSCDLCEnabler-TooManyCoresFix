#include "MemUtil.h"
#include "VirtualMemory.h"
#include "winternl.h"

cMemUtil MemUtil;
cVirtualMemory VirtualMemory;

bool cMemUtil::PatchAdr(LPVOID dst, LPVOID src, size_t len) {
	DWORD oldProtect, dummy;  
	NTSTATUS ret;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	SIZE_T pageSize = si.dwPageSize;

	LPVOID pageStart = (LPVOID)((uintptr_t)dst & ~(pageSize - 1));
	SIZE_T pageOffset = (uintptr_t)dst - (uintptr_t)pageStart;

	SIZE_T totalLength = pageOffset + len;
	const HANDLE CurrentProcess = GetCurrentProcess();

	VirtualMemory.CheckMemoryProtection(dst);

	ret = VirtualMemory.RedirectedProtectVirtualMemory(pageStart, totalLength, PAGE_EXECUTE_READWRITE, &oldProtect);
	if (!NT_SUCCESS(ret)) {
		printf_s("Failed to change memory protection. Status: 0x%08X\n", ret);
		return false;
	}
	else
		printf_s("Managed to change. Status: 0x%08X.\n", ret);
	
	VirtualMemory.CheckMemoryProtection(dst);

	memcpy(dst, src, len);

	ret = VirtualMemory.RedirectedProtectVirtualMemory(pageStart, totalLength, oldProtect, &dummy);
	if (!NT_SUCCESS(ret)) {
		printf_s("Failed to restore memory protection. Status: 0x%08X\n", ret);
		return false;
	}

	printf_s("Patched %zu bytes successfully at address %p\n", len, dst);
	return true;
}

bool cMemUtil::PlaceHook(void* hookSpot, void* ourFunct, int len)
{
	if (len < 5)
		return false;

	ULONG oldProtect, dummy;
	NTSTATUS ret;

	SYSTEM_INFO si;
	GetSystemInfo(&si);
	SIZE_T pageSize = si.dwPageSize;

	LPVOID pageStart = (LPVOID)((uintptr_t)hookSpot & ~(pageSize - 1));
	SIZE_T pageOffset = (uintptr_t)hookSpot - (uintptr_t)pageStart;

	SIZE_T totalLength = pageOffset + len;

	LPVOID hookAdr = hookSpot;
	ret = VirtualMemory.RedirectedProtectVirtualMemory(pageStart, totalLength, PAGE_EXECUTE_READWRITE, &oldProtect);

	if (!NT_SUCCESS(ret)) {
		printf_s("Failed to change memory protection. Status: 0x%08X\n", ret);
		return false;
	}
	else
		printf_s("Managed to change. Status: 0x%08X\n", ret);

	memset(hookAdr, 0x90, len);

	DWORD relativeAddr = ((DWORD)ourFunct - (DWORD)hookSpot) - 5;

	*(BYTE*)hookSpot = 0xE9;
	*(DWORD*)((DWORD)hookSpot + 1) = relativeAddr;

	ret = VirtualMemory.RedirectedProtectVirtualMemory(pageStart, totalLength, oldProtect, &dummy);

	return true;
}

uintptr_t cMemUtil::FindDMAAddy(uintptr_t ptr, std::vector<unsigned int> offsets)
{
	uintptr_t addr = ptr;
	for (unsigned int i = 0; i < offsets.size(); ++i)
	{
		addr = *(uintptr_t*)addr;

		if (addr == NULL)
			return NULL;

		addr += offsets[i];
	}
	return addr;
}

bool bCompare(const BYTE* pData, const byte* bMask, const char* szMask) {
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;
	return (*szMask) == NULL;
}

uint8_t* cMemUtil::FindPattern(uint32_t dwAddress, size_t dwLen, uint8_t* bMask, char* szMask) {
	for (DWORD i = 0; i < dwLen; i++)
		if (bCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (byte*)(dwAddress + i);
	return NULL;
}

uintptr_t cMemUtil::ReadPtr(uintptr_t adr) {
	if (adr == NULL)
		return NULL;

	return *(uintptr_t*)adr;
}
