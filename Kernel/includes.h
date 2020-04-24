#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <IntSafe.h>


#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)
#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )


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


typedef enum _SYSTEM_INFORMATION_CLASS {

	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemNextEventIdInformation,
	SystemEventIdsInformation,
	SystemCrashDumpInformation,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemPlugPlayBusInformation,
	SystemDockInformation,
	SystemProcessorSpeedInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation

} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_PROCESS_INFORMATION {

	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;


typedef struct _PEB_LDR_DATA {

	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {

	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {

	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;

} PEB, * PPEB;

typedef union _EXHANDLE
{
	struct
	{
		int TagBits : 2;
		int Index : 30;
	} u;
	void* GenericHandleOverlay;
	ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;

typedef struct _HANDLE_TABLE_ENTRY {
	union
	{
		ULONG_PTR VolatileLowValue;
		ULONG_PTR LowValue;
		struct _HANDLE_TABLE_ENTRY_INFO* InfoTable;
		struct
		{
			ULONG_PTR Unlocked : 1;
			ULONG_PTR RefCnt : 16;
			ULONG_PTR Attributes : 3;
			ULONG_PTR ObjectPointerBits : 44;
		};
	};
	union
	{
		ULONG_PTR HighValue;
		struct _HANDLE_TABLE_ENTRY* NextFreeHandleEntry;
		union _EXHANDLE LeafHandleValue;
		struct
		{
			ULONG GrantedAccessBits : 25;
			ULONG NoRightsUpgrade : 1;
			ULONG Spare : 6;
		};
	};

	ULONG TypeInfo;

} HANDLE_TABLE_ENTRY, * PHANDLE_TABLE_ENTRY;


typedef struct _HANDLE_TABLE {

	ULONG TableCode;
	PEPROCESS QuotaProcess;
	PVOID UniqueProcessId;
	EX_PUSH_LOCK HandleLock;
	LIST_ENTRY HandleTableList;
	EX_PUSH_LOCK HandleContentionEvent;
	PVOID DebugInfo;
	LONG ExtraInfoPages;
	ULONG Flags;
	ULONG StrictFIFO : 1;
	LONG FirstFreeHandle;
	PVOID LastFreeHandleEntry;
	LONG HandleCount;
	ULONG NextHandleNeedingPool;

} HANDLE_TABLE, * PHANDLE_TABLE;


typedef BOOLEAN(*tEX_ENUMERATE_HANDLE_ROUTINE)(
	IN PHANDLE_TABLE HandleTable,
	IN PHANDLE_TABLE_ENTRY HandleTableEntry,
	IN HANDLE Handle,
	IN PVOID EnumParameter
	);

typedef BOOLEAN(*tExEnumHandleTable)(
	IN PHANDLE_TABLE HandleTable,
	IN tEX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
	IN PVOID EnumParameter,
	OUT PHANDLE Handle
	);


HANDLE_ELEVATION GlobalHandleElevation = { 0 };
HANDLE GlobalHandle = nullptr;

extern "C" {
	NTKERNELAPI 
	NTSTATUS 
	IoCreateDriver(
		PUNICODE_STRING DriverName, 
		PDRIVER_INITIALIZE InitializationFunction
	);

	NTKERNELAPI 
	PVOID 
	PsGetProcessSectionBaseAddress(
		PEPROCESS Process
	);

	NTKERNELAPI 
	PPEB 
	NTAPI 
	PsGetProcessPeb(
		PEPROCESS Process
	);

	NTKERNELAPI
	NTSTATUS
	MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	NTSTATUS
	NTAPI
	ZwQuerySystemInformation(
		_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
		_Inout_ PVOID SystemInformation,
		_In_ ULONG SystemInformationLength,
		_Out_opt_ PULONG ReturnLength
	);

	NTSYSCALLAPI 
	NTSTATUS 
	NTAPI 
	ZwProtectVirtualMemory(
		HANDLE ProcessHandle, 
		PVOID* BaseAddress, 
		PSIZE_T RegionSize, 
		ULONG NewAccessProtection, 
		PULONG OldAccessProtection
	);

	NTKERNELAPI
	VOID
	FASTCALL
	ExfUnblockPushLock(
		IN OUT PEX_PUSH_LOCK PushLock,
		IN OUT PVOID WaitBlock
	);
}