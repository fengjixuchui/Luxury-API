#pragma once

#include <iostream>
#include <iomanip>
#include <vector>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

#include <string>
#include <filesystem>
#include <random>

#include <shlobj.h>
#include <winternl.h>
#include <Shlwapi.h>

#include <accctrl.h>
#include <aclapi.h>
#include <shlobj_core.h>

#include <thread>
#include <mutex>
#include <iphlpapi.h>

#include <CommCtrl.h>
#include <WinUser.h>
#include <Winioctl.h>

#include <sysinfoapi.h>
#include <tchar.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#define RANDOM_CAPS        0
#define RANDOM_LOWERCASE   1
#define RANDOM_MIXED       2


#define NtCurrentProcess() (HANDLE(-1))


#define space(x) for(int i = 0; i <= x; i++) {	\
					std::cout << std::endl;		\
				}



typedef enum _POOL_TYPE {

	NonPagedPool,
	NonPagedPoolExecute,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS,
	MaxPoolType,
	NonPagedPoolBase,
	NonPagedPoolBaseMustSucceed,
	NonPagedPoolBaseCacheAligned,
	NonPagedPoolBaseCacheAlignedMustS,
	NonPagedPoolSession,
	PagedPoolSession,
	NonPagedPoolMustSucceedSession,
	DontUseThisTypeSession,
	NonPagedPoolCacheAlignedSession,
	PagedPoolCacheAlignedSession,
	NonPagedPoolCacheAlignedMustSSession,
	NonPagedPoolNx,
	NonPagedPoolNxCacheAligned,
	NonPagedPoolSessionNx

} POOL_TYPE;


typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {

	HANDLE HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG GrantedAccess;
	ULONG ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;

} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;



typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {

	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;

}SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;


typedef struct _SYSTEM_HANDLE_INFORMATION {

	DWORD NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[ANYSIZE_ARRAY];

} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



typedef struct _THREAD_BASIC_INFORMATION {

	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	LONG					Priority;
	LONG	                BasePriority;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


typedef struct _OBJECT_BASIC_INFORMATION {

	ULONG                   Attributes;
	ACCESS_MASK             GrantedAccess;
	ULONG                   HandleCount;
	ULONG                   ReferenceCount;
	ULONG                   PagedPoolUsage;
	ULONG                   NonPagedPoolUsage;
	ULONG                   Reserved[3];
	ULONG                   NameInformationLength;
	ULONG                   TypeInformationLength;
	ULONG                   SecurityDescriptorLength;
	LARGE_INTEGER           CreationTime;

} OBJECT_BASIC_INFORMATION, * POBJECT_BASIC_INFORMATION;


typedef struct _OBJECT_NAME_INFORMATION {

	UNICODE_STRING          Name;
	WCHAR                   NameBuffer[0];

} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;


typedef struct _OBJECT_DATA_INFORMATION {

	BOOLEAN                 InheritHandle;
	BOOLEAN                 ProtectFromClose;

} OBJECT_DATA_INFORMATION, * POBJECT_DATA_INFORMATION;


typedef struct _OBJECT_TYPE_INFORMATION {

	UNICODE_STRING          TypeName;
	ULONG                   TotalNumberOfHandles;
	ULONG                   TotalNumberOfObjects;
	WCHAR                   Unused1[8];
	ULONG                   HighWaterNumberOfHandles;
	ULONG                   HighWaterNumberOfObjects;
	WCHAR                   Unused2[8];
	ACCESS_MASK             InvalidAttributes;
	GENERIC_MAPPING         GenericMapping;
	ACCESS_MASK             ValidAttributes;
	BOOLEAN                 SecurityRequired;
	BOOLEAN                 MaintainHandleCount;
	USHORT                  MaintainTypeList;
	POOL_TYPE               PoolType;
	ULONG                   DefaultPagedPoolCharge;
	ULONG                   DefaultNonPagedPoolCharge;

} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;



typedef NTSYSAPI NTSTATUS(NTAPI* tNtQueryVirtualMemory)(
	HANDLE hProcess,
	PVOID BaseAddress,
	INT MemoryInformationClass,
	PVOID MemoryInformation,
	SIZE_T MemoryInformationLength,
	PSIZE_T ReturnLength
	);


typedef NTSYSAPI NTSTATUS(NTAPI* tNtReadVirtualMemory)(
	HANDLE hProcess,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesRead OPTIONAL
	);


typedef NTSYSAPI NTSTATUS(NTAPI* tNtWriteVirtualMemory)(
	HANDLE hProcess,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToWrite,
	PULONG NumberOfBytesWritten OPTIONAL
	);


typedef NTSTATUS(NTAPI* tNtQuerySystemInformation)(
	DWORD SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);


typedef NTSTATUS (NTAPI* tNtQueryInformationProcess)(
	IN HANDLE hProcess,
	IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength
	);


typedef NTSTATUS(NTAPI* tNtQueryInformationThread) (
	IN HANDLE	ThreadHandle,
	IN INT		ThreadInformationClass,
	OUT PVOID	ThreadInformation,
	IN ULONG	ThreadInformationLength,
	OUT PULONG	ReturnLength OPTIONAL
	);


typedef NTSTATUS(NTAPI* tNtQueryTimerResolution) (
	OUT PULONG MinimumResolution,
	OUT PULONG MaximumResolution,
	OUT PULONG CurrentResolution
	);

typedef NTSTATUS(NTAPI* tNtSuspendResumeProcess)(
	IN HANDLE hProcess
	);


typedef NTSTATUS(NTAPI* tNtGetSetContextThread)(
	HANDLE ThreadHandle,
	PCONTEXT ThreadContext
	);


typedef NTSTATUS(NTAPI* tRtlCompareUnicodeString)(
	_In_ PUNICODE_STRING String1,
	_In_ PUNICODE_STRING String2,
	_In_ BOOLEAN         CaseInSensitive
	);


typedef NTSTATUS(NTAPI* tRtlGetVersion)(
	_Out_ PRTL_OSVERSIONINFOW lpVersionInformation
	);


typedef NTSTATUS(NTAPI* tZwLoadDriver)(
	PUNICODE_STRING DriverServiceName
	);


typedef NTSTATUS(NTAPI* tNtQueryObject)(
	HANDLE Object,
	OBJECT_INFORMATION_CLASS ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);


tNtQueryVirtualMemory pNtQueryVirtualMemory = nullptr;
tNtQuerySystemInformation pNtQuerySystemInformation = nullptr;
tNtReadVirtualMemory pNtReadVirtualMemory = nullptr;
tNtWriteVirtualMemory pNtWriteVirtualMemory = nullptr;
tNtQueryInformationProcess pNtQueryInformationProcess = nullptr;
tNtQueryInformationThread pNtQueryInformationThread = nullptr;
tNtQueryTimerResolution pNtQueryTimerResolution = nullptr;
tNtSuspendResumeProcess pNtSuspendProcess = nullptr;
tNtSuspendResumeProcess pNtResumeProcess = nullptr;
tNtGetSetContextThread pNtGetContextThread = nullptr;
tNtGetSetContextThread pNtSetContextThread = nullptr;
tNtQueryObject pNtQueryObject = nullptr;
tRtlCompareUnicodeString pRtlCompareUnicodeString = nullptr;
tRtlGetVersion pRtlGetVersion = nullptr;
tZwLoadDriver pZwLoadDriver = nullptr;


NTSTATUS NtQueryVirtualMemory(HANDLE hProcess, PVOID BaseAddress, INT MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
NTSTATUS NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, DWORD SystemInformationLength, PDWORD ReturnLength);
NTSTATUS NtReadVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesRead);
NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesWritten);
NTSTATUS NtQueryInformationProcess(HANDLE hProcess, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, INT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL);
NTSTATUS NtQueryTimerResolution(PULONG MinimumResolution, PULONG MaximumResolution, PULONG CurrentResolution);
NTSTATUS NtSuspendProcess(HANDLE hProcess);
NTSTATUS NtResumeProcess(HANDLE hProcess);
NTSTATUS NtGetContextThread(HANDLE hThread, PCONTEXT ThreadContext);
NTSTATUS NtSetContextThread(HANDLE hThread, PCONTEXT ThreadContext);
NTSTATUS NtQueryObject(HANDLE Object, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);
NTSTATUS RtlCompareUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSesitive);
NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW pVersionInfo);
NTSTATUS ZwLoadDriver(PUNICODE_STRING DriverServiceName);


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
	return OpenProcess(MAXIMUM_ALLOWED, false, ProcessID);
}


DWORD64 GetBaseAddress(const wchar_t* ProcessName, HANDLE hProcess) {
	HMODULE Modules[1024];
	DWORD SizeRequired = 0;
	wchar_t Name[MAX_PATH];

	if (K32EnumProcessModules(hProcess, Modules, sizeof(Modules), &SizeRequired)) {
		for (auto i = 0; i < (SizeRequired / sizeof(HMODULE)); i++) {
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


template <typename T>
T ReadMemory(HANDLE hProcess, DWORD64 Address, SIZE_T Size) {
	T ReadData = {};
	ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&ReadData), Size, nullptr);
	return ReadData;
}


template <typename T>
BOOL WriteMemory(HANDLE	hProcess, DWORD64 Address, T Data, SIZE_T Size) {
	return WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&Data), Size, nullptr);
}


template <typename T>
T CopyProcessMemory(HANDLE hProcess, DWORD64 Address, SIZE_T Size, BOOL ReadOperation, T Data) {
	if (ReadOperation == TRUE) {
		T ReadData = {};
		ReadProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&ReadData), Size, nullptr);
		return ReadData;
	}
	else {
		WriteProcessMemory(hProcess, reinterpret_cast<PVOID>(Address), static_cast<PVOID>(&Data), Size, nullptr);
		return {};
	}
}


DWORD64 ReadPointerChain(HANDLE hProcess, DWORD64 Base, int NumberOfPointers, ...) {
	va_list List;
	va_start(List, NumberOfPointers);

	for (int i = 0; i < NumberOfPointers; ++i) {
		Base = ReadMemory<DWORD64>(hProcess, Base + va_arg(List, DWORD64), sizeof(DWORD64));
	} va_end(List);

	return Base;
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


BOOL CompareData(const BYTE* Data, const BYTE* Signature, const char* Mask) {
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


STORAGE_DEVICE_DESCRIPTOR* QueryDiskInformation() {
	DWORD IoRetBytes{ NULL };
    	STORAGE_DESCRIPTOR_HEADER Header{ NULL };
	STORAGE_PROPERTY_QUERY QueryInfo{ StorageDeviceProperty, PropertyStandardQuery };

	HANDLE hDisk{ CreateFileW(L"\\\\.\\PhysicalDrive0", 0, 0, nullptr, OPEN_EXISTING, 0, nullptr) };

	if (hDisk != INVALID_HANDLE_VALUE) {
		if (DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &QueryInfo, sizeof(QueryInfo),&Header, sizeof(Header), &IoRetBytes, nullptr)) {
			if (auto DiskInfo{ static_cast<STORAGE_DEVICE_DESCRIPTOR*>(VirtualAlloc(nullptr, Header.Size, MEM_COMMIT, PAGE_READWRITE)) }) {
				DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY, &QueryInfo, sizeof(QueryInfo), DiskInfo, Header.Size, &IoRetBytes, nullptr);
				return DiskInfo;
			}
		}
	}

	return nullptr;
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

std::string RemoveWhitespaces(std::string);


BOOL EnumerateWindows(const char* WindowName) {
	struct Params {
		BOOL Result;
		const char* Name;
	};

	auto WindowEnumCallback = [](HWND Window, LPARAM LParam) -> BOOL {
		auto Args = (Params*)LParam;
		auto Size = GetWindowTextLengthA(Window);
		auto WindowText = new char[Size + 1ull];

		GetWindowTextA(Window, WindowText, Size + 1);
		Args->Result = (strcmp(RemoveWhitespaces(WindowText).c_str(), Args->Name) == 0 ? TRUE : FALSE);
		return (!Args->Result);
	};

	Params Args = { 0, WindowName };
	EnumWindows(WindowEnumCallback, reinterpret_cast<LPARAM>(&Args));
	return Args.Result;
}


BOOL WindowScanA(const char* WindowName) {
	return FindWindowA(nullptr, WindowName) ? TRUE : FALSE;
}


BOOL WindowScanW(const wchar_t* WindowName) {
	return FindWindowW(nullptr, WindowName) ? TRUE : FALSE;
}


BOOL EnumerateDrivers() {
	PVOID Drivers[1024];
	DWORD RequiredSize = NULL;

	if (K32EnumDeviceDrivers(Drivers, sizeof(Drivers), &RequiredSize)) {
		auto DriverCount = RequiredSize / sizeof(PVOID);
		for (int i = 0; i < DriverCount; i++) {
			wchar_t Buffer[256];
			K32GetDeviceDriverBaseNameW(Drivers[i], Buffer, 256);
		}
		return TRUE;
	}
	return FALSE;
}


BOOL IsDriverLoaded(wchar_t* DriverName) {
	PVOID Drivers[1024];
	DWORD RequiredSize = NULL;

	if (K32EnumDeviceDrivers(Drivers, sizeof(Drivers), &RequiredSize)) {
		auto DriverCount = RequiredSize / sizeof(PVOID);
		for (int i = 0; i < DriverCount; i++) {
			wchar_t Buffer[256];
			K32GetDeviceDriverBaseNameW(Drivers[i], Buffer, 256);

			if (!wcscmp(Buffer, DriverName)) {
				return TRUE;
			}
		}
	} 
	
	return FALSE;
}


DWORD64 ResolveRelativeAddress(HANDLE hProcess, DWORD64 RIP, DWORD InstructionLength) {
	DWORD RelativeOffset{ 0 };

	ReadProcessMemory(hProcess, 
			  reinterpret_cast<PVOID>(RIP + InstructionLength - 4), 
			  &RelativeOffset, 
			  sizeof(DWORD), 
			  nullptr);

	return RIP + InstructionLength + RelativeOffset;
}


BOOL KeyWasPressed(int Key) {
	return GetAsyncKeyState(Key);
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

HANDLE SpawnThread(PVOID StartRoutine, PVOID LP = nullptr, DWORD* ThreadId = nullptr) {
	return CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(StartRoutine), LP, 0, ThreadId);
}

void AppendString(std::string& SourceString, int NumberOfStrings, ...) {
	va_list List;
	va_start(List, NumberOfStrings);

	for (int i = 0; i < NumberOfStrings; ++i) {
		auto ToAppend = va_arg(List, char*);
		SourceString.append(ToAppend);
	} va_end(List);
}


BOOL StringToBool(std::string SourceString) {
	if (SourceString == "false" || SourceString == "False" || SourceString == "FALSE") {
		return FALSE;
	} return TRUE;
}


int SecondsToMilliseconds(int Seconds) {
	return Seconds * 1000;
}


int MinutesToSeconds(int Minutes) {
	return Minutes * 60;
}


int MinutesToMilliseconds(int Minutes) {
	return ((Minutes * 60) * 1000);
}


void SleepS(int Seconds) {
	Sleep(SecondsToMilliseconds(Seconds));
}


void SleepM(int Minutes) {
	Sleep(MinutesToMilliseconds(Minutes));
}


std::string GetTime() {
	SYSTEMTIME Time = { 0 };
	GetLocalTime(&Time);

	std::string TimeString = std::to_string(Time.wHour);
	AppendString(TimeString, 4, ":", std::to_string(Time.wMinute), ":", std::to_string(Time.wSecond));

	return TimeString;
}


int RandomInteger(int Min = 0, int Max = 200) {
	std::random_device RandomDevice;
	std::mt19937 RNG(RandomDevice());
	std::uniform_int_distribution<> Dist(Min, Max);

	return Dist(RNG);
}


float RandomFloat(float Min = 0.0f, float Max = 100.0f) {
Start:

	std::random_device RandomDevice;
	std::mt19937 RNG(RandomDevice());
	std::uniform_int_distribution<> Dist(Min, Max);

	float MainFloat = Dist(RNG);
	int Factorial = Dist(RNG);

	std::string MainString = std::to_string(MainFloat);

	if (MainFloat < 100.0f) {
		MainString.replace(3, 5, std::to_string(Factorial));
	}
	else if (MainFloat < 1000.0f) {
		MainString.replace(4, 6, std::to_string(Factorial));
	}
	else if (MainFloat < 1000.0f) {
		MainString.replace(5, 7, std::to_string(Factorial));
	}
	else if (MainFloat < 100000.0f) {
		MainString.replace(6, 8, std::to_string(Factorial));
	}
	else if (MainFloat < 10000000.0f) {
		MainString.replace(8, 10, std::to_string(Factorial));
	}
	else {
		return 0.0f;
	}

	float RandomFloat = std::stof(MainString);

	if (RandomFloat > Max) {
		RandomFloat = Max;
	} if (RandomFloat < 0.0f) {
		goto Start;
	} return RandomFloat;
}


std::string RandomStringA(std::size_t Length, BOOL Numbers, DWORD Capitalization) {
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

	std::uniform_int_distribution<> Dist(0, Alphabet.size() - 1);

	for (std::size_t i = 0; i < Length; ++i) {
		GeneratedString += Alphabet[Dist(RNG)];
	}

	return GeneratedString;
}


std::wstring RandomStringW(std::size_t Length, BOOL Numbers, DWORD Capitalization) {
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

	std::uniform_int_distribution<> Dist(0, Alphabet.size() - 1);

	for (std::size_t i = 0; i < Length; ++i) {
		GeneratedString += Alphabet[Dist(RNG)];
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


template <typename T>
T GetFunctionPointer(const char* Module, const char* Function) {
	if (Module && Function) {
		return reinterpret_cast<T>(GetProcAddress(LoadLibraryA(Module), Function));
	} else {
		return nullptr;
	}
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
	std::flush(std::cout);
	std::cout << Text;
}


VOID Print(int NumberOfStrings, ...) {
	va_list List;
	va_start(List, NumberOfStrings);

	for (int i = 0; i < NumberOfStrings; ++i) {
		std::cout << va_arg(List, char*);
	} va_end(List);
}


VOID PrintS(std::string Text) {
	std::flush(std::cout);
	std::cout << Text << "\n";
}


VOID Print(std::string Text, std::string Text2) {
	std::flush(std::cout);
	std::cout << Text << Text2;
}


VOID PrintS(std::string Text, std::string Text2) {
	std::flush(std::cout);
	std::cout << Text << Text2 << "\n";
}


VOID PrintHex(PVOID Hex) {
	std::flush(std::cout);
	std::cout << "0x" << std::uppercase << std::hex << Hex;
}


VOID PrintHexS(PVOID Hex) {
	std::flush(std::cout);
	std::cout << "0x" << std::uppercase << std::hex << Hex << "\n";
}


VOID PrintHex(DWORD64 Hex) {
	std::flush(std::cout);
	std::cout << "0x" << std::uppercase << std::hex << Hex;
}


VOID PrintHexS(DWORD64 Hex) {
	std::flush(std::cout);
	std::cout << "0x" << std::uppercase << std::hex << Hex << "\n";
}


VOID PrintFloat(float Value, int Precision) {
	std::flush(std::cout);
	std::cout << std::fixed << std::setprecision(Precision) << Value;
}


VOID PrintFloatS(float Value, int Precision) {
	std::flush(std::cout);
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


RTL_OSVERSIONINFOW GetOSInfo() {
	RTL_OSVERSIONINFOW OSInfo = { 0 };
	RtlGetVersion(&OSInfo);
	return OSInfo;
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


	Process(std::wstring Name, HANDLE Handle) {
		this->Name = Name;
		this->ProcessID = GetProcessID(Name.c_str());
		this->Handle = (Handle == nullptr ? GetHandle(this->ProcessID) : Handle);
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


	template <typename T>
	T Read(DWORD64 Address, SIZE_T Size) const {
		return ReadMemory<T>(this->Handle, Address, Size);
	}


	template <typename T>
	bool Write(DWORD64 Address, T Data, SIZE_T Size) const {
		return WriteMemory<T>(this->Handle, Address, Data, Size);
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


	std::vector<DWORD> GetThreadList(DWORD ProcessId) {
		std::vector<DWORD> Threads = { 0 };
		HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessId);
		THREADENTRY32 Thread{ sizeof(THREADENTRY32) };

		if (Thread32First(Snapshot, &Thread)) {
			do {
				if (Thread.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(Thread.th32OwnerProcessID)) {
					if (Thread.th32OwnerProcessID == ProcessId) {
						Threads.push_back(Thread.th32ThreadID);
					}
				} Thread.dwSize = sizeof(Thread);
			} while (Thread32Next(Snapshot, &Thread));
		} return Threads;
	}


	DWORD GetMainThreadId() {
		HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, this->ProcessID);
		THREADENTRY32 Thread{ sizeof(THREADENTRY32) };

		if (Thread32First(Snapshot, &Thread)) {
			do {
				if (Thread.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(Thread.th32OwnerProcessID)) {
					if (Thread.th32OwnerProcessID == this->ProcessID) {
						CloseHandle(Snapshot);
						return Thread.th32ThreadID;
					}
				} Thread.dwSize = sizeof(Thread);
			} while (Thread32Next(Snapshot, &Thread));
		}

		CloseHandle(Snapshot);
		return NULL;
	}


	HANDLE GetMainThread() {
		return OpenThread(THREAD_ALL_ACCESS, false, GetMainThreadId());
	}


	DWORD64 GetThreadStack() {
		THREAD_BASIC_INFORMATION ThreadInfo = { 0 };
		MODULEINFO Kernel32Info = { 0 };
		DWORD SizeRequired = NULL;
		DWORD64 StackTop = NULL;
		DWORD64 ThreadStack = NULL;

		auto MainThread = GetMainThread();
		auto Status = NtQueryInformationThread(MainThread, 0, &ThreadInfo, sizeof(ThreadInfo), &SizeRequired);

		GetModuleInformation(this->Handle, GetModuleHandle(L"kernel32.dll"), &Kernel32Info, sizeof(Kernel32Info));
		StackTop = Read<DWORD64>(reinterpret_cast<DWORD64>(ThreadInfo.TebBaseAddress) + 0x8, sizeof(DWORD64));
		CloseHandle(MainThread);

		if (StackTop) {
			DWORD64* Buffer = new DWORD64[4096];

			if (ReadProcessMemory(this->Handle, reinterpret_cast<PVOID>(StackTop - 4096), Buffer, 4096, NULL)) {
				for (auto i = 4096 / 8 - 1; i >= 0; --i) {
					if (Buffer[i] >= (DWORD64)Kernel32Info.lpBaseOfDll && Buffer[i] <= (DWORD64)Kernel32Info.lpBaseOfDll + Kernel32Info.SizeOfImage) {
						ThreadStack = StackTop - 4096 + i * 8ull;
						break;
					}
				}
			} delete[] Buffer;
		} return ThreadStack;
	}


	~Process() {
		CloseHandle(this->Handle);
	}
};


class SliderObject;
typedef void(*SliderCallback)(PVOID);
std::unique_ptr<SliderObject> gSliderObject{ nullptr };
WNDPROC gSliderObjectProcedure{ nullptr };
LRESULT CALLBACK SliderObjectProcedure(HWND hWindow, UINT Message, WPARAM WP, LPARAM LP);


class SliderObject {
public:

	SliderCallback OnValueChanged{ nullptr };
	SliderCallback OnExit{ nullptr };
	SliderCallback OnTick{ nullptr };

	HWND Parent{ nullptr };
	HWND Display{ nullptr };
	HWND Slider{ nullptr };

	int Value{ 0 };
	int MinimumValue{ 0 };
	int MaximumValue{ 0 };
	int DefaultValue{ 0 };
	LPCSTR WindowName{ nullptr };
	DWORD SliderStyle{ 0 };
	COLORREF BkgColor{ 0 };


	template <typename T = SliderCallback>
	SliderObject Init(
		T OnValueChanged,
		T OnExit,
		T OnTick,
		std::string_view BkgColor = "Navy",
		int MinimumValue = 1,
		int MaximumValue = 100,
		int DefaultValue = 100,
		LPCSTR WindowName = "", 
		DWORD SliderStyle = WS_CHILD | TBS_HORZ | WS_VISIBLE | TBS_TOOLTIPS,
		DWORD ParentStyle = WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU, 
		int X = -1,
		int Y = -1,
		int Width = 300,
		int Height = 40
	) 
	{
		this->OnValueChanged = reinterpret_cast<SliderCallback>(OnValueChanged);
		this->OnExit = reinterpret_cast<SliderCallback>(OnExit);
		this->OnTick = reinterpret_cast<SliderCallback>(OnTick);
		this->BkgColor = StringToColor(BkgColor.data());
		this->Value = DefaultValue;
		this->MinimumValue = MinimumValue;
		this->MaximumValue = MaximumValue;
		this->DefaultValue = DefaultValue;
		this->WindowName = WindowName;
		this->SliderStyle = SliderStyle;
		
		this->Parent = CreateWindowExA(0, (LPCSTR)WC_DIALOG, WindowName, ParentStyle, 0, 0, 0, 0, nullptr, nullptr, nullptr, nullptr);
		this->Slider = CreateWindowExW(0, TRACKBAR_CLASSW, nullptr, SliderStyle, X, Y, Width, Height, this->Parent, nullptr, nullptr, nullptr);

		gSliderObject = std::make_unique<SliderObject>(*this);
		gSliderObjectProcedure = (WNDPROC)SetWindowLongPtrW(gSliderObject->Parent, GWLP_WNDPROC, (LONG_PTR)SliderObjectProcedure);
	
		SendMessageW(gSliderObject->Slider, TBM_SETRANGEMIN, gSliderObject->MinimumValue, gSliderObject->MinimumValue);
		SendMessageW(gSliderObject->Slider, TBM_SETRANGEMAX, gSliderObject->MinimumValue, gSliderObject->MaximumValue);
		SendMessageW(gSliderObject->Slider, TBM_SETPOS, 0, gSliderObject->DefaultValue);

		SetWindowPos(gSliderObject->Parent, HWND_TOP, 0, 0, 312, 60, SWP_SHOWWINDOW);
		ShowWindow(gSliderObject->Parent, SW_SHOW);

		MSG Message = { 0 };

		do {
			DispatchMessageW(&Message);
			this->OnTick(this);
		} while (GetMessageW(&Message, nullptr, 0, 0));
	}

	void SetWindowName(std::string_view Name) {
		SetWindowTextA(this->Parent, Name.data());
		this->WindowName = Name.data();
	}

	template <typename T>
	T GetValue() {
		return reinterpret_cast<T>(this->Value);
	}
};


LRESULT CALLBACK SliderObjectProcedure(HWND hWindow, UINT Message, WPARAM WP, LPARAM LP) {
	switch (Message) {
		case WM_HSCROLL: {
			if (reinterpret_cast<HWND>(LP) == gSliderObject->Slider) {
				SendMessageW(
					gSliderObject->Display, 
					WM_SETTEXT, 
					NULL, 
					(LPARAM)std::to_wstring(
						gSliderObject->Value = SendMessage(
							gSliderObject->Slider, 
							TBM_GETPOS, 
							0, 
							0
						)).c_str());

				gSliderObject->OnValueChanged(gSliderObject.get());
			}
		} break;

		case WM_CLOSE: {
			gSliderObject->OnExit(gSliderObject.get());
			PostQuitMessage(0);
		} break;

		case WM_CTLCOLORSTATIC: {
			if (RGB(255, 255, 255) == gSliderObject->BkgColor) {
				SetTextColor((HDC)WP, RGB(0, 0, 0));
			} else {
				SetTextColor((HDC)WP, RGB(255, 255, 255));
			}
			SetBkColor((HDC)WP, gSliderObject->BkgColor);
			return (BOOL)CreateSolidBrush(gSliderObject->BkgColor);
		} break;

		case WM_CTLCOLORDLG: {
			if (RGB(255, 255, 255) == gSliderObject->BkgColor) {
				SetTextColor((HDC)WP, RGB(0, 0, 0));
			} else {
				SetTextColor((HDC)WP, RGB(255, 255, 255));
			}
			SetBkColor((HDC)WP, gSliderObject->BkgColor);
			return (BOOL)CreateSolidBrush(gSliderObject->BkgColor);
		} break;
	}
	
	return CallWindowProcW(gSliderObjectProcedure, hWindow, Message, WP, LP);
}






VOID InitImports() {
	pNtQueryVirtualMemory = GetFunctionPointer<tNtQueryVirtualMemory>("ntdll.dll", "NtQueryVirtualMemory");
	pNtQuerySystemInformation = GetFunctionPointer<tNtQuerySystemInformation>("ntdll.dll", "NtQuerySystemInformation");
	pNtReadVirtualMemory = GetFunctionPointer<tNtReadVirtualMemory>("ntdll.dll", "NtReadVirtualMemory");
	pNtWriteVirtualMemory = GetFunctionPointer<tNtWriteVirtualMemory>("ntdll.dll", "NtWriteVirtualMemory");
	pNtQueryInformationProcess = GetFunctionPointer<tNtQueryInformationProcess>("ntdll.dll", "NtQueryInformationProcess");
	pNtQueryInformationThread = GetFunctionPointer<tNtQueryInformationThread>("ntdll.dll", "NtQueryInformationThread");
	pNtQueryTimerResolution = GetFunctionPointer<tNtQueryTimerResolution>("ntdll.dll", "NtQueryTimerResolution");
	pNtSuspendProcess = GetFunctionPointer<tNtSuspendResumeProcess>("ntdll.dll", "NtSuspendProcess");
	pNtResumeProcess = GetFunctionPointer<tNtSuspendResumeProcess>("ntdll.dll", "NtResumeProcess");
	pNtGetContextThread = GetFunctionPointer<tNtGetSetContextThread>("ntdll.dll", "NtGetContextThread");
	pNtSetContextThread = GetFunctionPointer<tNtGetSetContextThread>("ntdll.dll", "NtSetContextThread");
	pNtQueryObject = GetFunctionPointer	<tNtQueryObject>("ntdll.dll", "NtQueryObject");
	pRtlCompareUnicodeString = GetFunctionPointer<tRtlCompareUnicodeString>("ntdll.dll", "RtlCompareUnicodeString");
	pRtlGetVersion = GetFunctionPointer<tRtlGetVersion>("ntdll.dll", "RtlGetVersion");
	pZwLoadDriver = GetFunctionPointer<tZwLoadDriver>("ntdll.dll", "ZwLoadDriver");
}


NTSTATUS NtQueryVirtualMemory(HANDLE hProcess, PVOID BaseAddress, INT MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
	if (pNtQueryVirtualMemory == nullptr) {
		pNtQueryVirtualMemory = GetFunctionPointer<tNtQueryVirtualMemory>("ntdll.dll", "NtQueryVirtualMemory");
	} return pNtQueryVirtualMemory(hProcess, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
}


NTSTATUS NtQuerySystemInformation(DWORD SystemInformationClass, PVOID SystemInformation, DWORD SystemInformationLength, PDWORD ReturnLength) {
	if (pNtQuerySystemInformation == nullptr) {
		pNtQuerySystemInformation = GetFunctionPointer<tNtQuerySystemInformation>("ntdll.dll", "NtQuerySystemInformation");
	} return pNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
}


NTSTATUS NtReadVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesRead) {
	if (pNtReadVirtualMemory == nullptr) {
		pNtReadVirtualMemory = GetFunctionPointer<tNtReadVirtualMemory>("ntdll.dll", "NtReadVirtualMemory");
	} return pNtReadVirtualMemory(hProcess, Address, Buffer, Size, BytesRead);
}


NTSTATUS NtWriteVirtualMemory(HANDLE hProcess, PVOID Address, PVOID Buffer, DWORD Size, PDWORD BytesWritten) {
	if (pNtWriteVirtualMemory == nullptr) {
		pNtWriteVirtualMemory = GetFunctionPointer<tNtWriteVirtualMemory>("ntdll.dll", "NtWriteVirtualMemory");
	} return pNtWriteVirtualMemory(hProcess, Address, Buffer, Size, BytesWritten);
}


NTSTATUS NtQueryInformationProcess(HANDLE hProcess, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength) {
	if (pNtQueryInformationProcess == nullptr) {
		pNtQueryInformationProcess = GetFunctionPointer<tNtQueryInformationProcess>("ntdll.dll", "NtQueryInformationProcess");
	} return pNtQueryInformationProcess(hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
}


NTSTATUS NtQueryInformationThread(HANDLE ThreadHandle, INT ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength OPTIONAL) {
	if (pNtQueryInformationThread == nullptr) {
		pNtQueryInformationThread = GetFunctionPointer<tNtQueryInformationThread>("ntdll.dll", "NtQueryInformationThread");
	} return pNtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
}


NTSTATUS NtQueryTimerResolution(PULONG MinimumResolution, PULONG MaximumResolution, PULONG CurrentResolution) {
	if (pNtQueryTimerResolution == nullptr) {
		pNtQueryTimerResolution = GetFunctionPointer<tNtQueryTimerResolution>("ntdll.dll", "NtQueryTimerResolution");
	} return pNtQueryTimerResolution(MinimumResolution, MaximumResolution, CurrentResolution);
}


NTSTATUS NtSuspendProcess(HANDLE hProcess) {
	if (pNtSuspendProcess == nullptr) {
		pNtSuspendProcess = GetFunctionPointer<tNtSuspendResumeProcess>("ntdll.dll", "NtSuspendProcess");
	} return pNtSuspendProcess(hProcess);
}


NTSTATUS NtResumeProcess(HANDLE hProcess) {
	if (pNtResumeProcess == nullptr) {
		pNtResumeProcess = GetFunctionPointer<tNtSuspendResumeProcess>("ntdll.dll", "NtResumeProcess");
	} return pNtResumeProcess(hProcess);
}


NTSTATUS NtGetContextThread(HANDLE hThread, PCONTEXT ThreadContext) {
	if (pNtGetContextThread == nullptr) {
		pNtGetContextThread = GetFunctionPointer<tNtGetSetContextThread>("ntdll.dll", "NtGetContextThread");
	} return pNtGetContextThread(hThread, ThreadContext);
}


NTSTATUS NtSetContextThread(HANDLE hThread, PCONTEXT ThreadContext) {
	if (pNtSetContextThread == nullptr) {
		pNtSetContextThread = GetFunctionPointer<tNtGetSetContextThread>("ntdll.dll", "NtSetContextThread");
	} return pNtSetContextThread(hThread, ThreadContext);
}


NTSTATUS NtQueryObject(HANDLE Object, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength) {
	if (pNtQueryObject == nullptr) {
		pNtQueryObject = GetFunctionPointer<tNtQueryObject>("ntdll.dll", "NtQueryObject");
	} return pNtQueryObject(Object, ObjectInformationClass, ObjectInformation, ObjectInformationLength, ReturnLength);
}


NTSTATUS RtlCompareUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOLEAN CaseInSesitive) {
	if (pRtlCompareUnicodeString == nullptr) {
		pRtlCompareUnicodeString = GetFunctionPointer<tRtlCompareUnicodeString>("ntdll.dll", "RtlCompareUnicodeString");
	} return pRtlCompareUnicodeString(String1, String2, CaseInSesitive);
}


NTSTATUS RtlGetVersion(PRTL_OSVERSIONINFOW pVersionInfo) {
	if (pRtlGetVersion == nullptr) {
		pRtlGetVersion = GetFunctionPointer<tRtlGetVersion>("ntdll.dll", "RtlGetVersion");
	} return pRtlGetVersion(pVersionInfo);
}


NTSTATUS ZwLoadDriver(PUNICODE_STRING DriverServiceName) {
	if (pZwLoadDriver == nullptr) {
		pZwLoadDriver = GetFunctionPointer<tZwLoadDriver>("ntdll.dll", "ZwLoadDriver");
	} return pZwLoadDriver(DriverServiceName);
}


BOOL IsEqualUnicodeString(PUNICODE_STRING String1, PUNICODE_STRING String2, BOOL CaseInSesitive) {
	if (!RtlCompareUnicodeString(String1, String2, CaseInSesitive)) {
		return TRUE;
	} return FALSE;
}
