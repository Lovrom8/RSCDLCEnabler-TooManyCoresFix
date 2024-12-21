#pragma once

#include <iostream>
#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

class cVirtualMemory 
{
public:
	NTSTATUS NtProtectVirtualMemory(IN HANDLE process, IN OUT void** baseAddress, IN OUT PSIZE_T size, IN ULONG newProtection, OUT PULONG oldProtection);
	void CheckMemoryProtection(void* address);
	uint32_t GetTextSectionLength();
	uint32_t GetTextSectionAddress();
};

extern cVirtualMemory VirtualMemory;