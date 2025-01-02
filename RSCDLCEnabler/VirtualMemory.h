#pragma once

#include <iostream>
#include <windows.h>
#include <vector>
#include "Util.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef NTSTATUS(WINAPI* Type_NtProtectVirtualMemory)(HANDLE /*ProcessHandle*/, LPVOID* /*BaseAddress*/, SIZE_T* /*NumberOfBytesToProtect*/, ULONG /*NewAccessProtection*/, PULONG /*OldAccessProtection*/);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect
);

class cVirtualMemory 
{
public:
	NTSTATUS NtProtectVirtualMemoryDirect(IN HANDLE process, IN OUT void** baseAddress, IN OUT size_t* size, IN uint32_t newProtection, OUT uint32_t* oldProtection);
	void CheckMemoryProtection(void* address);
	uint32_t GetTextSectionLength();
	uint32_t GetTextSectionAddress();
	void InitMemoryManagement();
	NTSTATUS RedirectedProtectVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);

	Type_NtProtectVirtualMemory pfnNtProtectVirtualMemory = nullptr;
	bool IsLPVersion = false;
};

extern cVirtualMemory VirtualMemory;