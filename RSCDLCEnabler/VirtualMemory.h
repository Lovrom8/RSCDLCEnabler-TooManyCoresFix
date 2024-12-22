#pragma once

#include <iostream>
#include <windows.h>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

class cVirtualMemory 
{
public:
	NTSTATUS NtProtectVirtualMemoryDirect(IN HANDLE process, IN OUT void** baseAddress, IN OUT size_t* size, IN uint32_t newProtection, OUT uint32_t* oldProtection);
	void CheckMemoryProtection(void* address);
	uint32_t GetTextSectionLength();
	uint32_t GetTextSectionAddress();
};

extern cVirtualMemory VirtualMemory;