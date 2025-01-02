#include "VirtualMemory.h"

NTSTATUS cVirtualMemory::NtProtectVirtualMemoryDirect(IN HANDLE process, IN OUT void** baseAddress, IN OUT size_t* size, IN uint32_t newProtection, OUT uint32_t* oldProtection) {
	typedef NTSTATUS(WINAPI* tNtPVM)(IN HANDLE ProcessHandle, IN OUT void** BaseAddress, IN OUT size_t* NumberOfBytesToProtect, IN uint32_t NewAccessProtection, OUT uint32_t* OldAccessProtection);

	static tNtPVM ntProtectVirtualMemory = nullptr;

	if (ntProtectVirtualMemory == nullptr) {
		const auto ntdll = GetModuleHandleW(L"ntdll.dll");
		if (ntdll == nullptr) return STATUS_DLL_NOT_FOUND;

		ntProtectVirtualMemory = reinterpret_cast<tNtPVM>(GetProcAddress(ntdll, "NtProtectVirtualMemory"));
		if (ntProtectVirtualMemory == nullptr) return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	return ntProtectVirtualMemory(process, baseAddress, size, newProtection, oldProtection);
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

NTSTATUS cVirtualMemory::RedirectedProtectVirtualMemory(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
	const HANDLE ProcessHandle = GetCurrentProcess();

	if (IsLPVersion && pfnNtProtectVirtualMemory != nullptr)
	{
		std::cout << "Using the patched NtProtectVirtualMemory" << std::endl;
		SIZE_T NumberOfBytesToProtect = dwSize;
		return (pfnNtProtectVirtualMemory(ProcessHandle, &lpAddress, &NumberOfBytesToProtect, flNewProtect, lpflOldProtect));
	}

	std::cout << "Using the syscall for NtProtectVirtualMemory" << std::endl;
	return NtProtectVirtualMemory(ProcessHandle, &lpAddress, &dwSize, flNewProtect, lpflOldProtect);
}

static bool LoadNtDllFileContents(std::vector<char>& outBuffer)
{
	HMODULE ntDllModule = GetModuleHandleA("ntdll.dll");
	if (!ntDllModule)
	{
		std::cerr << "Failed to get ntdll.dll module" << std::endl;
		return false;
	}

	char ntDllPath[MAX_PATH + 1]{ 0 };
	if (GetModuleFileNameA(ntDllModule, ntDllPath, sizeof(ntDllPath)) == 0)
	{
		std::cerr << "Failed to get ntdll.dll path" << std::endl;
		return false;
	}

	FILE* file = nullptr;
	fopen_s(&file, ntDllPath, "rb");
	if (file == nullptr)
	{
		std::cerr << "Failed to open ntdll.dll for read" << std::endl;
		return false;
	}

	bool result = false;

	if (fseek(file, 0, SEEK_END) != 0)
	{
		std::cerr << "Failed to get ntdll.dll file size" << std::endl;
	}
	else
	{
		long fileSize = ftell(file);
		if (fileSize > 0)
		{
			outBuffer.resize(fileSize);

			fseek(file, 0, SEEK_SET);

			if (fread(outBuffer.data(), fileSize, 1, file) != 1)
			{
				std::cerr << "Failed to get ntdll.dll file size" << std::endl;
			}
			else
			{
				result = true;
			}
		}
	}

	fclose(file);
	file = nullptr;

	return result;
}

std::vector<unsigned char> GetUntouchedVirtualProtectBytes(unsigned numBytes)
{
	constexpr const char* fnName = "NtProtectVirtualMemory";
	std::wstring tmpFilePath = GetGamePath() + L"CDLC.ntdll.tmp";
	HMODULE untouchedMod = LoadLibraryW(tmpFilePath.c_str());
	HANDLE tmpFile = nullptr;
	std::vector<char> ntDllFileContents;

	if (!untouchedMod)
	{
		std::cout << "Loading ntdll.dll to memory" << std::endl;
		if (!LoadNtDllFileContents(ntDllFileContents))
		{
			return {};
		}
		else
		{
			std::cout << "Loaded ntdll.dll to memory: " << (ntDllFileContents.size() / 1024) << " kB" << std::endl;
		}

		tmpFile = CreateFileW(tmpFilePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN, nullptr);
		if (tmpFile == nullptr)
		{
			std::cerr << "Failed to open temporary file for writing" << std::endl;
			return {};
		}
		else
		{
			DWORD numBytesWritten = 0;

			const BOOL writeResult = WriteFile(tmpFile, ntDllFileContents.data(), ntDllFileContents.size(), &numBytesWritten, nullptr);
			if (!writeResult || numBytesWritten < ntDllFileContents.size())
			{
				std::cerr << "Error when writing to temporary file. Wrote " << numBytesWritten << " out of " << ntDllFileContents.size() << " bytes" << std::endl;
			}

			CloseHandle(tmpFile);
			tmpFile = nullptr;
		}

		untouchedMod = LoadLibraryW(tmpFilePath.c_str());
	}

	std::vector<unsigned char> result;
	if (untouchedMod)
	{
		void* proc = GetProcAddress(untouchedMod, fnName);

		if (!proc)
		{
			std::cout << "Failed to get " << fnName << " proc" << std::endl;
		}
		else
		{
			result.resize(numBytes);
			memcpy(result.data(), proc, numBytes);
		}

		FreeLibrary(untouchedMod);
	}

	DeleteFileW(tmpFilePath.c_str());
	return result;
}


static void* GenerateFixedProtectVirtualMemoryFn(void* originalFnPtr)
{
	constexpr unsigned numBytes = 10;
	std::cout << "Generating function to patch memory" << std::endl;
	std::vector<unsigned char> origBytes = GetUntouchedVirtualProtectBytes(5);

	if (origBytes.size() == 0)
	{
		std::cerr << "Failed get original data for patch memory function" << std::endl;
		return nullptr;
	}

	if (origBytes[0] != 0xb8)
	{
		char tmp[8];
		snprintf(tmp, 4, "%02x", origBytes[0]);
		std::cerr << "Unexpected instruction in original data of patch memory function: " << tmp << std::endl;
		return nullptr;
	}

	const long absDstJumpToOriginal = ((long)(BYTE*)originalFnPtr) + 5; // We want to jump to the instruction following the first "mov"
	BYTE* fnBytes = (BYTE*)VirtualAlloc(NULL, numBytes, MEM_COMMIT, PAGE_READWRITE);
	if (!fnBytes)
	{
		std::cerr << "Failed to allocate memory for new function" << std::endl;
		return nullptr;
	}

	BYTE* cursorBytes = fnBytes;
	memcpy(cursorBytes, origBytes.data(), 5);
	cursorBytes += 5;
	const long offset = (long)cursorBytes;
	*cursorBytes = 0xe9;
	++cursorBytes;
	const long targetRelAddress = absDstJumpToOriginal - ((long)offset + 5);
	*((long*)cursorBytes) = targetRelAddress;
	DWORD oldProtect = 0;

	if (!VirtualProtect(fnBytes, numBytes, PAGE_EXECUTE, &oldProtect))
	{
		VirtualFree(fnBytes, 0, MEM_RELEASE);
		fnBytes = nullptr;
	}
	return fnBytes;
}

void cVirtualMemory::InitMemoryManagement()
{
	HMODULE ntdllMod = GetModuleHandleA("ntdll.dll");
	if (!ntdllMod)
	{
		std::cerr << "Failed get handle for ntdll.dll" << std::endl;
		return;
	}

	pfnNtProtectVirtualMemory = (Type_NtProtectVirtualMemory)GetProcAddress(ntdllMod, "NtProtectVirtualMemory");
	if (!pfnNtProtectVirtualMemory)
	{
		std::cerr << "Failed get original proc address for NtProtectVirtualMemory in ntdll.dll" << std::endl;
		pfnNtProtectVirtualMemory = nullptr;
		return;
	}

	void* fnFixedProtectVirtualMemory = GenerateFixedProtectVirtualMemoryFn(pfnNtProtectVirtualMemory);
	if (fnFixedProtectVirtualMemory)
	{
		pfnNtProtectVirtualMemory = (Type_NtProtectVirtualMemory)fnFixedProtectVirtualMemory;
	}
}

