#pragma once

#include <iostream>
#include <iomanip>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <string>
#include <filesystem>
#include <random>

#include <shlobj.h>
#include <Subauth.h>
#include <Shlwapi.h>

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")


#define RANDOM_CAPS        0
#define RANDOM_LOWERCASE   1
#define RANDOM_MIXED       2


#define space(x) for(int i = 0; i <= x; i++) {	\
					std::cout << std::endl;		\
				}



typedef NTSYSAPI NTSTATUS(NTAPI* tNTReadVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesRead   OPTIONAL
	);


typedef NTSYSAPI NTSTATUS(NTAPI* tNTWriteVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten   OPTIONAL
	);


typedef NTSTATUS(NTAPI* tNTQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


typedef NTSTATUS(NTAPI* tRtlCompareUnicodeString)(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive
	);


typedef NTSTATUS(NTAPI* tRtlGetVersion)(
	_Out_ PRTL_OSVERSIONINFOW lpVersionInformation
	);


tNTQuerySystemInformation pNtQuerySystemInformation = nullptr;
tNTReadVirtualMemory pNtReadVirtualMemory = nullptr;
tNTWriteVirtualMemory pNtWriteVirtualMemory = nullptr;
tRtlCompareUnicodeString pRtlCompareUnicodeString = nullptr;
tRtlGetVersion pRtlGetVersion = nullptr;


NTSTATUS NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, DWORD SystemInformationLength, PDWORD ReturnLength);
NTSTATUS NtReadVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesRead);
NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesWritten);
NTSTATUS RtlCompareUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSesitive);
NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW pVersionInfo);




DWORD GetProcessID(const wchar_t* ProcessName) {
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W Process{ sizeof(PROCESSENTRY32W) };

	if (Process32FirstW(Snapshot, &Process)) {
		do {
			if (!wcscmp(ProcessName, Process.szExeFile)) {
				CloseHandle(Snapshot);
				return Process.th32ProcessID;
			}
		} while (Process32NextW(Snapshot, &Process));
	}
	CloseHandle(Snapshot);
	return NULL;
}


DWORD GetModuleSize(DWORD ProcessID, const wchar_t* ModuleName) {
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, ProcessID);
	MODULEENTRY32W Module{ sizeof(MODULEENTRY32W) };

	if (Module32FirstW(Snapshot, &Module)) {
		do {
			if (!wcscmp(ModuleName, Module.szModule)) {
				CloseHandle(Snapshot);
				return Module.modBaseSize;
			}
		} while (Module32NextW(Snapshot, &Module));
	}
	CloseHandle(Snapshot);
	return NULL;
}


HANDLE GetHandle(DWORD ProcessID) {
	return OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);
}


DWORD64 GetBaseAddress(const wchar_t* ProcessName, HANDLE hProcess) {
	HMODULE Modules[1024];
	DWORD v = 0;
	wchar_t Name[MAX_PATH];

	if (K32EnumProcessModules(hProcess, Modules, sizeof(Modules), &v)) {
		for (auto i = 0; i < (v / sizeof(HMODULE)); i++) {
			if (K32GetModuleFileNameExW(hProcess, Modules[i], Name, sizeof(Name) / sizeof(wchar_t))) {
				std::wstring ModuleName = Name;
				if (ModuleName.find(ProcessName) != std::string::npos) {
					return reinterpret_cast<DWORD64>(Modules[i]);
				}
			}
		}
	}
	return NULL;
}


DWORD GetProcessIDFromWindowA(const char* WindowName) {
	DWORD ProcessID = NULL;
	HWND hWindow = FindWindowA(nullptr, WindowName);

	GetWindowThreadProcessId(hWindow, &ProcessID);
	return ProcessID;
}


DWORD GetProcessIDFromWindowW(const wchar_t* WindowName) {
	DWORD ProcessID = NULL;
	HWND hWindow = FindWindowW(nullptr, WindowName);

	GetWindowThreadProcessId(hWindow, &ProcessID);
	return ProcessID;
}


template <typename dynamic>
dynamic ReadMemory(HANDLE hProcess, DWORD64 Address, SIZE_T Size) {
	dynamic r = {};
	ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&r), Size, nullptr);
	return r;
}


template <typename dynamic>
BOOL WriteMemory(HANDLE	hProcess, DWORD64 Address, dynamic Data, SIZE_T Size) {
	return WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&Data), Size, nullptr);
}


template <typename dynamic>
dynamic CopyProcessMemory(HANDLE hProcess, DWORD64 Address, SIZE_T Size, BOOL ReadOperation, dynamic Data) {
	if (ReadOperation == TRUE) {
		dynamic r = {};
		ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&r), Size, nullptr);
		return r;
	}
	else {
		WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&Data), Size, nullptr);
		return {};
	}
}


PVOID AllocateMemory(SIZE_T Size) {
	return VirtualAlloc(nullptr, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}


BOOL FreeMemory(PVOID Buffer) {
	return VirtualFree(Buffer, NULL, MEM_RELEASE);
}


PVOID AllocateMemoryEx(HANDLE hProcess, DWORD64 Address, SIZE_T Size) {
	return VirtualAllocEx(hProcess, (PVOID)Address, Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}


BOOL FreeMemoryEx(HANDLE hProcess, DWORD64 Address) {
	return VirtualFreeEx(hProcess, (PVOID)Address, NULL, MEM_RELEASE);
}


BOOL CompareData(const BYTE * Data, const BYTE * Signature, const char* Mask) {
	for (; *Mask; ++Mask, ++Data, ++Signature) {
		if (*Mask == 'x' && *Data != *Signature) {
			return FALSE;
		}
	}
	return (*Mask == NULL);
}


DWORD64 PatternFinder(HANDLE hProcess, DWORD64 Address, DWORD64 Size, const char* Signature, const char* Mask) {
	auto Buffer = AllocateMemory(Size);

	ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(Address), Buffer, Size, nullptr);

	for (DWORD64 i = 0; i < Size; i++) {

		if (CompareData(const_cast<BYTE*>(static_cast<BYTE*>(Buffer) + i), reinterpret_cast<const BYTE*>(Signature), Mask)) {
			FreeMemory(Buffer);
			return Address + i;
		}
	}

	FreeMemory(Buffer);
	return NULL;
}


BOOL KillProcess(const wchar_t* ProcessName) {
	return TerminateProcess(OpenProcess(PROCESS_TERMINATE, FALSE, GetProcessID(ProcessName)), 0);
}


BOOL IsProcessRunning(const wchar_t* ProcessName) {
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W Process{ sizeof(PROCESSENTRY32W) };

	if (Process32FirstW(Snapshot, &Process)) {
		do {
			if (!wcscmp(ProcessName, Process.szExeFile)) {
				CloseHandle(Snapshot);
				return TRUE;
			}

		} while (Process32NextW(Snapshot, &Process));
	}

	CloseHandle(Snapshot);
	return FALSE;
}


BOOL BeingDebugged(BOOL	CurrentProcess, const wchar_t* ProcessName OPTIONAL) {
	BOOL DebuggerPresent = FALSE;

	if (CurrentProcess) {
		if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &DebuggerPresent)) {
			if (DebuggerPresent) {
				return TRUE;
			}
		}
		return FALSE;
	}
	else {
		if (CheckRemoteDebuggerPresent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetProcessID(ProcessName)), &DebuggerPresent)) {
			if (DebuggerPresent) {
				return TRUE;
			}
		}
		return FALSE;
	}
	return FALSE;
}


BOOL WindowScanA(char* WindowName) {
	auto wnd = FindWindowA(nullptr, WindowName);
	return (!wnd) ? FALSE : TRUE;
}


BOOL WindowScanW(wchar_t* WindowName) {
	auto wnd = FindWindowW(nullptr, WindowName);
	return (!wnd) ? FALSE : TRUE;
}


BOOL DoesFileExist(const char* FileName) {
	HANDLE hFile;

	hFile = CreateFileA(
		FileName, GENERIC_ALL,
		0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (GetLastError() == ERROR_FILE_NOT_FOUND) {
		return FALSE;
	}
	else {
		CloseHandle(hFile);
		return TRUE;
	}
}


BOOL StringToBool(std::string SourceString) {
	if (SourceString == "false" || SourceString == "False" || SourceString == "FALSE") {
		return FALSE;
	} return TRUE;
}


std::string GenerateRandomStringA(std::size_t Length, BOOL Numbers, DWORD Capitalization) {
	std::string GeneratedString;
	std::string Alphabet;

	std::random_device RandomDevice;
	std::mt19937 RNG(RandomDevice());

	if ((Numbers) && Capitalization == RANDOM_CAPS) {
		Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_CAPS) {
		Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	}
	else if ((Numbers) && Capitalization == RANDOM_LOWERCASE) {
		Alphabet = "abcdefghijklmnopqrstuvwxyz1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_LOWERCASE) {
		Alphabet = "abcdefghijklmnopqrstuvwxyz";
	}
	else if ((Numbers) && Capitalization == RANDOM_MIXED) {
		Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_MIXED) {
		Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	}

	std::uniform_int_distribution<> dist(0, Alphabet.size() - 1);

	for (std::size_t i = 0; i < Length; ++i) {
		GeneratedString += Alphabet[dist(RNG)];
	}

	return GeneratedString;
}


std::wstring GenerateRandomStringW(std::size_t Length, BOOL Numbers, DWORD Capitalization) {
	std::wstring GeneratedString;
	std::wstring Alphabet;

	std::random_device RandomDevice;
	std::mt19937 RNG(RandomDevice());

	if ((Numbers) && Capitalization == RANDOM_CAPS) {
		Alphabet = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_CAPS) {
		Alphabet = L"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	}
	else if ((Numbers) && Capitalization == RANDOM_LOWERCASE) {
		Alphabet = L"abcdefghijklmnopqrstuvwxyz1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_LOWERCASE) {
		Alphabet = L"abcdefghijklmnopqrstuvwxyz";
	}
	else if ((Numbers) && Capitalization == RANDOM_MIXED) {
		Alphabet = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	}
	else if ((!Numbers) && Capitalization == RANDOM_MIXED) {
		Alphabet = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	}

	std::uniform_int_distribution<> dist(0, Alphabet.size() - 1);

	for (std::size_t i = 0; i < Length; ++i) {
		GeneratedString += Alphabet[dist(RNG)];
	}

	return GeneratedString;
}


UNICODE_STRING ReturnUnicodeString(wchar_t* SourceString) {
	UNICODE_STRING UnicodeString = { 0 };
	SIZE_T Size = 0ul;
	const SIZE_T MaxSize = (0xffff & ~1) - sizeof(UNICODE_NULL);

	if (SourceString) {
		Size = wcslen(SourceString) * sizeof(wchar_t);
		__analysis_assume(Size <= MaxSize);

		if (Size > MaxSize) {
			Size = MaxSize;
		}

		UnicodeString.Length = static_cast<USHORT>(Size);
		UnicodeString.MaximumLength = static_cast<USHORT>(Size) + sizeof(UNICODE_NULL);
	}
	else {
		UnicodeString.Length = 0;
		UnicodeString.MaximumLength = 0;
	}

	UnicodeString.Buffer = static_cast<wchar_t*>(SourceString);
	return UnicodeString;
}


VOID Launch(std::string Path) {
	Path.insert(0, "start ");
	system(Path.c_str());
}


VOID PrintPeriods(int Count, int ms) {
	for (int i = 0; i < Count; i++) {
		std::cout << ".";
		Sleep(ms);
	}
}


VOID Print(std::string Text) {
	std::cout << Text;
}


VOID PrintS(std::string Text) {
	std::cout << Text << "\n";
}


VOID Print(std::string Text, std::string Text2) {
	std::cout << Text << Text2;
}


VOID PrintS(std::string Text, std::string Text2) {
	std::cout << Text << Text2 << "\n";
}


VOID PrintHex(PVOID Hex) {
	std::cout << "0x" << std::uppercase << std::hex << Hex;
}


VOID PrintHexS(PVOID Hex) {
	std::cout << "0x" << std::uppercase << std::hex << Hex << "\n";
}


VOID PrintHex(DWORD64 Hex) {
	std::cout << "0x" << std::uppercase << std::hex << Hex;
}


VOID PrintHexS(DWORD64 Hex) {
	std::cout << "0x" << std::uppercase << std::hex << Hex << "\n";
}


VOID PrintFloat(float Value, int Precision) {
	std::cout << std::fixed << std::setprecision(Precision) << Value;
}


VOID PrintFloatS(float Value, int Precision) {
	std::cout << std::fixed << std::setprecision(Precision) << Value << "\n";
}


DWORD DecToHex(int Value) {
	std::string h = "";
	char hex[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

	while (Value > 0) {
		auto r = Value % 16;
		h = hex[r] + h;
		Value = Value / 16;
	}
	return std::stoul(h);
}


COLORREF StringToColor(std::string SourceString) {
	if (SourceString == "white" || SourceString == "White" || SourceString == "WHITE")
		return RGB(255, 255, 255);
	if (SourceString == "black" || SourceString == "Black" || SourceString == "BLACK")
		return RGB(0, 0, 0);
	if (SourceString == "red" || SourceString == "Red" || SourceString == "RED")
		return RGB(255, 0, 0);
	if (SourceString == "blue" || SourceString == "Blue" || SourceString == "BLUE")
		return RGB(0, 0, 255);
	if (SourceString == "green" || SourceString == "Green" || SourceString == "GREEN")
		return RGB(0, 128, 0);
	if (SourceString == "purple" || SourceString == "Purple" || SourceString == "PURPLE")
		return RGB(100, 0, 135);
	if (SourceString == "navy" || SourceString == "Navy" || SourceString == "NAVY")
		return RGB(0, 0, 128);
	if (SourceString == "maroon" || SourceString == "Maroon" || SourceString == "MAROON")
		return RGB(128, 0, 0);

	return RGB(255, 255, 255);
}


std::string RemoveWhitespaces(std::string SourceString) {
	auto Count = 0;

	for (auto i = 0; SourceString[i]; i++) {
		if (SourceString[i] != ' ') {
			SourceString[Count++] = SourceString[i];
		}
	}
	SourceString[Count] = '\0';
	return SourceString.c_str();
}


PVOID GetFunctionPointer(const char* Module, const char* Function) {
	if (Module && Function) {
		return static_cast<PVOID>(GetProcAddress(GetModuleHandleA(Module), Function));
	}
	else {
		return nullptr;
	}
}


VOID InitImports() {
	pNtQuerySystemInformation = static_cast<tNTQuerySystemInformation>(GetFunctionPointer("ntdll.dll", "NtQuerySystemInformation"));
	pNtReadVirtualMemory = static_cast<tNTReadVirtualMemory>(GetFunctionPointer("ntdll.dll", "NtReadVirtualMemory"));
	pNtWriteVirtualMemory = static_cast<tNTWriteVirtualMemory>(GetFunctionPointer("ntdll.dll", "NtWriteVirtualMemory"));
	pRtlCompareUnicodeString = static_cast<tRtlCompareUnicodeString>(GetFunctionPointer("ntdll.dll", "RtlCompareUnicodeString"));
	pRtlGetVersion = static_cast<tRtlGetVersion>(GetFunctionPointer("ntdll.dll", "RtlGetVersion"));
}


BOOL IsEqualUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOL CaseInSesitive) {
	if (pRtlCompareUnicodeString == nullptr) {
		pRtlCompareUnicodeString = static_cast<tRtlCompareUnicodeString>(GetFunctionPointer("ntdll.dll", "RtlCompareUnicodeString"));
	}
	if (!RtlCompareUnicodeString(String1, String2, CaseInSesitive)) {
		return TRUE;
	} return FALSE;
}


RTL_OSVERSIONINFOW GetOSInfo() {
	RTL_OSVERSIONINFOW OSInfo = { 0 };

	if (pRtlGetVersion == nullptr) {
		pRtlGetVersion = static_cast<tRtlGetVersion>(GetFunctionPointer("ntdll.dll", "RtlGetVersion"));
	}

	RtlGetVersion(&OSInfo);
	return OSInfo;
}


std::string OSMajorVersionToString(DWORD MajorVersion, DWORD MinorVersion) {
	if (MajorVersion == 10) {
		return "Windows 10";
	}

	if (MajorVersion == 6) {
		if (MinorVersion == 3) {
			return "Windows 8.1";
		}
		else if (MinorVersion == 2) {
			return "Windows 8";
		}
		else if (MinorVersion == 1) {
			return "Windows 7";
		}
	} return "Unsupported";
}


std::wstring OSMajorVersionToStringW(DWORD MajorVersion, DWORD MinorVersion) {
	if (MajorVersion == 10) {
		return L"Windows 10";
	}

	if (MajorVersion == 6) {
		if (MinorVersion == 3) {
			return L"Windows 8.1";
		}
		else if (MinorVersion == 2) {
			return L"Windows 8";
		}
		else if (MinorVersion == 1) {
			return L"Windows 7";
		}
	} return L"Unsupported";
}


std::string GetWinVer() {
	auto v = GetOSInfo();
	return OSMajorVersionToString(v.dwMajorVersion, v.dwMinorVersion);
}


std::wstring GetWinVerW() {
	auto v = GetOSInfo();
	return OSMajorVersionToStringW(v.dwMajorVersion, v.dwMinorVersion);
}


NTSTATUS NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, DWORD SystemInformationLength, PDWORD ReturnLength) {
	if (!pNtQuerySystemInformation) {
		InitImports();
	} return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}


NTSTATUS NtReadVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesRead) {
	if (!pNtReadVirtualMemory) {
		InitImports();
	} return pNtReadVirtualMemory(hProcess, Address, Buffer, Size, BytesRead);
}


NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesWritten) {
	if (!pNtWriteVirtualMemory) {
		InitImports();
	} return pNtWriteVirtualMemory(hProcess, Address, Buffer, Size, BytesWritten);
}


NTSTATUS RtlCompareUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSesitive) {
	if (!pRtlCompareUnicodeString) {
		InitImports();
	} return pRtlCompareUnicodeString(String1, String2, CaseInSesitive);
}


NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW pVersionInfo) {
	if (!pRtlGetVersion) {
		InitImports();
	} return pRtlGetVersion(pVersionInfo);
}




class Directories {
public:

	std::string Combine(std::string String1, std::string String2) {
		return String1.append(String2);
	}

	std::string Temp() {
		char Path[MAX_PATH + 1];
		GetTempPathA(MAX_PATH + 1, Path);
		return Path;
	}

	std::string Current() {
		char Buffer[MAX_PATH + 1];
		GetModuleFileNameA(nullptr, Buffer, sizeof(Buffer));
		PathRemoveFileSpecA(Buffer);
		std::string Path = Buffer;
		return Path.append("\\");
	}

	std::string Desktop() {
		char Buffer[MAX_PATH + 1];
		SHGetFolderPathA(nullptr, CSIDL_DESKTOP, nullptr, NULL, Buffer);
		std::string Path = Buffer;
		return Path.append("\\");
	}

	std::string System32() {
		char Buffer[MAX_PATH + 1];
		GetSystemDirectoryA(Buffer, sizeof(Buffer));
		std::string Path = Buffer;
		return Path.append("\\");
		return Path;
	}

	std::string CurrentExecutable() {
		char Buffer[MAX_PATH + 1];
		GetModuleFileNameA(nullptr, Buffer, sizeof(Buffer));
		return Buffer;
	}

	std::string CurrentDrive() {
		auto Path = Current();
		char Drive[3];
		Path.copy(Drive, 3, 0);
		return Drive;
	}




	std::wstring CombineW(std::wstring String1, std::wstring String2) {
		return String1.append(String2);
	}

	std::wstring TempW() {
		wchar_t Path[MAX_PATH + 1];
		GetTempPathW(MAX_PATH + 1, Path);
		return Path;
	}

	std::wstring CurrentW() {
		wchar_t Buffer[MAX_PATH + 1];
		GetModuleFileNameW(nullptr, Buffer, sizeof(Buffer));
		PathRemoveFileSpecW(Buffer);
		std::wstring Path = Buffer;
		return Path.append(L"\\");
	}

	std::wstring DesktopW() {
		wchar_t Buffer[MAX_PATH + 1];
		SHGetFolderPathW(nullptr, CSIDL_DESKTOP, nullptr, NULL, Buffer);
		std::wstring Path = Buffer;
		return Path.append(L"\\");
	}

	std::wstring System32W() {
		wchar_t Buffer[MAX_PATH + 1];
		GetSystemDirectoryW(Buffer, sizeof(Buffer));
		std::wstring Path = Buffer;
		return Path.append(L"\\");
		return Path;
	}

	std::wstring CurrentExecutableW() {
		wchar_t Buffer[MAX_PATH + 1];
		GetModuleFileNameW(nullptr, Buffer, sizeof(Buffer));
		return Buffer;
	}

	std::wstring CurrentDriveW() {
		auto Path = CurrentW();
		wchar_t Drive[3];
		Path.copy(Drive, 3, 0);
		return Drive;
	}
}; Directories Path;




class Process {
public:
	std::wstring Name = L"";
	DWORD ProcessID = 0;
	HANDLE Handle = 0;
	DWORD64 BaseAddress = 0;
	DWORD Size = 0;

	Process(std::wstring Name) {
		this->Name = Name;
		this->ProcessID = GetProcessID(Name.c_str());
		this->Handle = GetHandle(this->ProcessID);
		this->BaseAddress = GetBaseAddress(this->Name.c_str(), this->Handle);
		this->Size = GetModuleSize(this->ProcessID, this->Name.c_str());

	}

	bool IsValid() const {
		if (this->Name.c_str() != nullptr && this->ProcessID && this->Handle != INVALID_HANDLE_VALUE && this->BaseAddress) {
			return true;
		} return false;
	}

	void Print() const {
		std::wcout << L"Name: " << this->Name << "\n";
		std::cout << "ProcessID: " << std::dec << static_cast<int>(this->ProcessID) << "\n";
		std::cout << "Handle: " << std::uppercase << std::hex << this->Handle << "\n";
		std::cout << "Base Address: " << std::uppercase << std::hex << this->BaseAddress << "\n";
		std::cout << "Size: " << std::uppercase << std::hex << this->Size << "\n";
	}

	template <typename dynamic>
	dynamic Read(DWORD64 Address, SIZE_T Size) const {
		return ReadMemory<dynamic>(this->Handle, Address, Size);
	}

	template <typename dynamic>
	bool Write(DWORD64 Address, dynamic Data, SIZE_T Size) const {
		return WriteMemory<dynamic>(this->Handle, Address, Data, Size);
	}

	DWORD64 Scan(DWORD64 Start, DWORD Size, const char* Signature, const char* Mask) const {
		return PatternFinder(this->Handle, Start, Size, Signature, Mask);
	}

	DWORD64 Scan(const char* Signature, const char* Mask) const {
		return PatternFinder(this->Handle, this->BaseAddress, this->Size, Signature, Mask);
	}

	PVOID AllocateMemory(DWORD64 Address, SIZE_T Size) {
		return AllocateMemoryEx(this->Handle, Address, Size);
	}

	PVOID FreeMemory(DWORD64 Address) {
		FreeMemoryEx(this->Handle, Address);
	}

	bool IsDebuggerPresent() const {
		return BeingDebugged(true, this->Name.c_str());
	}

	bool IsRunning() const {
		return IsProcessRunning(this->Name.c_str());
	}

	bool IsConnectedToTCPTable() const {
		PMIB_TCPTABLE2 TcpTable = nullptr;
		DWORD TableSize = 0;

		GetTcpTable2(TcpTable, &TableSize, true);
		TcpTable = new MIB_TCPTABLE2[TableSize];

		if (!TcpTable) {
			return false;
		} if (GetTcpTable2(TcpTable, &TableSize, true) == NO_ERROR) {
			for (DWORD i = 0; i <= TcpTable->dwNumEntries; i++) {
				if (TcpTable->table[i].dwOwningPid == this->ProcessID && TcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB) {
					delete[] TcpTable;
					return true;
				}
			}
		} 
		delete[] TcpTable;
		return false;
	}

	~Process() {
		CloseHandle(this->Handle);
	}
};


typedef struct _PROCESS_DATA {

	const wchar_t*	Name;
	DWORD			ProcessID;
	PVOID			Address;
	PVOID			BaseAddress;
	DWORD			ModuleSize;
	PVOID			Data;
	SIZE_T			Size;
	SIZE_T			Bytes;
	BOOLEAN			ReadOperation;

}PROCESS_DATA, * PPROCESS_DATA;


typedef struct _HANDLE_ELEVATION {

	DWORD			ProcessID;
	ACCESS_MASK		AccessMask;
	HANDLE			Handle;
	PHANDLE			pHandle;

}HANDLE_ELEVATION, * PHANDLE_ELEVATION;


#define IO_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_COPY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_INIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_FREE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_OPEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ELEVATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C8, METHOD_BUFFERED, FILE_ANY_ACCESS)


class KernelProcess {
public:

	HANDLE hDriver = { 0 };
	std::wstring Name = L"";
	DWORD ProcessID = 0;
	DWORD64 BaseAddress = 0;
	DWORD Size = 0;

	KernelProcess(std::wstring Name) {
		this->hDriver = CreateFileW(L"\\\\.\\zwpsnt", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		this->Name = Name;

		PROCESS_DATA Data = { this->Name.c_str(), 0ul, nullptr, nullptr, 0ul, nullptr, 0ul, 0ul, 0 };
		ControlDriver(IO_INIT, &Data, sizeof(Data), &Data, sizeof(Data));

		this->ProcessID = Data.ProcessID;
		this->BaseAddress = reinterpret_cast<DWORD64>(Data.BaseAddress);
		this->Size = Data.ModuleSize;
	}

	bool IsValid() const {
		if (this->Name.c_str() != nullptr && this->ProcessID && this->BaseAddress && this->Size) {
			return true;
		} return false;
	}

	void Print() const {
		std::wcout << L"Name: " << this->Name << "\n";
		std::cout << "ProcessID: " << std::dec << static_cast<int>(this->ProcessID) << "\n";
		std::cout << "Base Address: " << std::uppercase << std::hex << this->BaseAddress << "\n";
		std::cout << "Size: " << std::uppercase << std::hex << this->Size << "\n";
	}

	DWORD GetProcessID() {
		PROCESS_DATA Data = { this->Name.c_str(), 0ul, nullptr, nullptr, 0ul, nullptr, 0ul, 0ul, 0 };
		ControlDriver(IO_PID, &Data, sizeof(Data), &Data, sizeof(Data));

		return Data.ProcessID;
	}

	template <typename dynamic>
	dynamic Read(DWORD64 Address, SIZE_T Size) const {
		PROCESS_DATA Data = { 0 };
		dynamic v = {};

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Address);
		Data.Data = &v;
		Data.Size = Size;
		Data.ReadOperation = true;

		ControlDriver(IO_COPY, &Data, sizeof(Data), &Data, sizeof(Data));

		return *reinterpret_cast<dynamic*>(&v);
	}

	template <typename dynamic>
	bool Write(DWORD64 Address, dynamic Value, SIZE_T Size) const {
		PROCESS_DATA Data = { 0 };

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Address);
		Data.Data = &Value;
		Data.Size = Size;
		Data.ReadOperation = false;

		ControlDriver(IO_COPY, &Data, sizeof(Data), &Data, sizeof(Data));
		
		return (Data.Bytes == Data.Size) ? true : false;
	}

	DWORD64 Scan(DWORD64 Start, DWORD64 Size, const char* Signature, const char* Mask) {
		PROCESS_DATA Data = { 0 };
		auto Buffer = AllocateMemory(Size);

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Start);
		Data.Size = Size;
		Data.Data = Buffer;
		Data.ReadOperation = TRUE;

		ControlDriver(IO_COPY, &Data, sizeof(Data), &Data, sizeof(Data));

		for (DWORD64 i = 0; i < Size; i++) {

			if (CompareData(const_cast<BYTE*>(static_cast<BYTE*>(Buffer) + i), reinterpret_cast<const BYTE*>(Signature), Mask)) {
				FreeMemory(Buffer);
				return Start + i;
			}
		}

		FreeMemory(Buffer);
		return NULL;
	}

	DWORD64 Scan(const char* Signature, const char* Mask) {
		return Scan(this->BaseAddress, this->Size, Signature, Mask);
	}

	PVOID AllocateVirtualMemory(DWORD64 Address, SIZE_T Size) {
		PROCESS_DATA Data = { 0 };

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Address);
		Data.Size = Size;

		ControlDriver(IO_ALLOC, &Data, sizeof(Data), &Data, sizeof(Data));
		
		return Data.Address;
	}

	void FreeVirtualMemory(DWORD64 Address) {
		PROCESS_DATA Data = { 0 };

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Address);

		ControlDriver(IO_FREE, &Data, sizeof(Data), &Data, sizeof(Data));
	}

	void ProtectVirtualMemory(DWORD64 Address, SIZE_T Size, DWORD Protection) {
		PROCESS_DATA Data = { 0 };

		Data.ProcessID = this->ProcessID;
		Data.Address = reinterpret_cast<PVOID>(Address);
		Data.Size = Size;
		Data.Bytes = Protection;

		ControlDriver(IO_PROTECT, &Data, sizeof(Data), &Data, sizeof(Data));
	}

	HANDLE ElevateHandle() {
		HANDLE hProcess = INVALID_HANDLE_VALUE;
		HANDLE_ELEVATION Data = { this->ProcessID, PROCESS_QUERY_LIMITED_INFORMATION, nullptr, &hProcess };
		ControlDriver(IO_OPEN, &Data, sizeof(Data), &Data, sizeof(Data));
		Data = { GetCurrentProcessId(), PROCESS_ALL_ACCESS, hProcess };
		ControlDriver(IO_ELEVATE, &Data, sizeof(Data), &Data, sizeof(Data));

		return hProcess;
	}

	BOOLEAN ControlDriver(DWORD IoCode, PVOID InputData, SIZE_T InputSize, PVOID OutputData, SIZE_T OutputSize) {
		DWORD Bytes = 0;
		return DeviceIoControl(this->hDriver, IoCode, InputData, InputSize, OutputData, OutputSize, &Bytes, NULL);
	}

	~KernelProcess() {
		CloseHandle(this->hDriver);
	}
};