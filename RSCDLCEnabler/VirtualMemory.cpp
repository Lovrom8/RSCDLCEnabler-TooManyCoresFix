#include "VirtualMemory.h"

NTSTATUS cVirtualMemory::NtProtectVirtualMemory(IN HANDLE process, IN OUT void** baseAddress, IN OUT PSIZE_T size, IN ULONG newProtection, OUT PULONG oldProtection) {
	typedef NTSTATUS(WINAPI* tNtPVM)(IN HANDLE ProcessHandle, IN OUT void** BaseAddress, IN OUT PSIZE_T NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);

	static tNtPVM ntProtectVirtualMemory = nullptr;

	if (ntProtectVirtualMemory == nullptr) {
		const auto ntdll = GetModuleHandleW(L"ntdll.dll");
		if (ntdll == nullptr) return STATUS_DLL_NOT_FOUND;

		ntProtectVirtualMemory = reinterpret_cast<tNtPVM>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
		if (ntProtectVirtualMemory == nullptr) return STATUS_ENTRYPOINT_NOT_FOUND;

		printf_s("NtProtectVirtualMemory loaded...\n");
	}

	return NtProtectVirtualMemory(process, baseAddress, size, newProtection, oldProtection);
}

uint32_t cVirtualMemory::GetTextSectionAddress() {
	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule) {
		std::cerr << "Failed to get base address of the host process." << std::endl;
		return 0;
	}

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader +
		ntHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (strncmp((char*)sectionHeaders[i].Name, ".text", 5) == 0) {

			DWORD textSectionVA = sectionHeaders[i].VirtualAddress;
			uint32_t textSectionAddress = (uint32_t)((BYTE*)hModule + textSectionVA);

			return textSectionAddress;
		}
	}

	std::cerr << "Failed to find the .text section." << std::endl;
	return 0;
}

uint32_t cVirtualMemory::GetTextSectionLength() {
	HMODULE hModule = GetModuleHandle(NULL);
	if (!hModule) {
		std::cerr << "Failed to get base address of the host process." << std::endl;
		return 0;
	}

	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);

	IMAGE_SECTION_HEADER* sectionHeaders = (IMAGE_SECTION_HEADER*)((BYTE*)&ntHeaders->OptionalHeader +
		ntHeaders->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
		if (strncmp((char*)sectionHeaders[i].Name, ".text", 5) == 0) {
			// Length of the .text section
			uint32_t textSectionLength = sectionHeaders[i].Misc.VirtualSize;

			return textSectionLength;
		}
	}

	std::cerr << "Failed to find the .text section." << std::endl;
	return 0;
}

void cVirtualMemory::CheckMemoryProtection(void* address) {
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(address, &mbi, sizeof(mbi))) {
		std::cout << "Current Protection: ";

		switch (mbi.Protect) {
		case PAGE_EXECUTE_READ:
			std::cout << "PAGE_EXECUTE_READ" << std::endl;
			break;
		case PAGE_READONLY:
			std::cout << "PAGE_READONLY" << std::endl;
			break;
		case PAGE_READWRITE:
			std::cout << "PAGE_READWRITE" << std::endl;
			break;
		case PAGE_EXECUTE_READWRITE:
			std::cout << "PAGE_EXECUTE_READWRITE" << std::endl;
			break;
		default:
			std::cout << "Other protection flag: " << mbi.Protect << std::endl;
		}
	}
	else {
		std::cerr << "VirtualQuery failed. Error: " << GetLastError() << std::endl;
	}
}
