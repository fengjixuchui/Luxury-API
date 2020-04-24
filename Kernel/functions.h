#pragma once
#include "includes.h"


PEPROCESS GetProcess(DWORD ProcessId) {
	PEPROCESS eProcess = nullptr;
	PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(ProcessId), &eProcess);
	return eProcess;
}


NTSTATUS GetBase(PPROCESS_DATA Data) {
	auto eProcess = GetProcess(Data->ProcessID);

	if (eProcess == nullptr) {
		return STATUS_UNSUCCESSFUL;
	}

	Data->BaseAddress = PsGetProcessSectionBaseAddress(eProcess);
	ObfDereferenceObject(eProcess);

	return (Data->BaseAddress != nullptr) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


NTSTATUS CopyProcessMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);

	if (eProcess == nullptr) {
		return STATUS_UNSUCCESSFUL;
	}

	if (Data->ReadOperation) {
		Status = MmCopyVirtualMemory(eProcess, Data->Address, IoGetCurrentProcess(), Data->Data, Data->Size, KernelMode, &Data->Bytes);
	}
	else {
		Status = MmCopyVirtualMemory(IoGetCurrentProcess(), Data->Data, eProcess, Data->Address, Data->Size, KernelMode, &Data->Bytes);
	}

	ObfDereferenceObject(eProcess);
	return Status;
}


void GetModuleSize(PPROCESS_DATA Data) {
	UNICODE_STRING ModuleName = RTL_CONSTANT_STRING(Data->Name);
	auto eProcess = GetProcess(Data->ProcessID);
	auto ModuleList = &(PsGetProcessPeb(eProcess)->Ldr->InLoadOrderModuleList);

	for (auto Entry = ModuleList->Flink; Entry != ModuleList; ) {
		auto Module = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (!RtlCompareUnicodeString(&Module->BaseDllName, &ModuleName, TRUE)) {
			ObfDereferenceObject(eProcess);
			Data->ModuleSize = Module->SizeOfImage;
		} Entry = Module->InLoadOrderLinks.Flink;
	} ObfDereferenceObject(eProcess);
}


NTSTATUS GetProcessID(PPROCESS_DATA Data) {
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING Process = RTL_CONSTANT_STRING(Data->Name);
	PVOID Buffer = nullptr;
	DWORD Size = 0;

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Size);
	Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, 'YRXL');

	if (Buffer == nullptr) {
		return NULL;
	}

	auto ProcessInformation = (PSYSTEM_PROCESS_INFORMATION)Buffer;
	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, Size, NULL);

	if (!NT_SUCCESS(Status)) {
		ExFreePoolWithTag(Buffer, 'YRXL');
		return NULL;
	} 
	
	for (;;) {
		if (!RtlCompareUnicodeString(&ProcessInformation->ImageName, &Process, TRUE)) {
			Data->ProcessID = reinterpret_cast<DWORD>(ProcessInformation->UniqueProcessId);
			break;
		} else if (ProcessInformation->NextEntryOffset) {
			ProcessInformation = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(ProcessInformation) + ProcessInformation->NextEntryOffset);
		} else {
			break;
		}
	}

	ExFreePoolWithTag(Buffer, 'YRXL');
	return Status;
}


PSYSTEM_PROCESS_INFORMATION GetProcessInfo(const wchar_t* Name) {
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING Process = RTL_CONSTANT_STRING(Name);
	PVOID Buffer = nullptr;
	DWORD Size = 0;
	static PSYSTEM_PROCESS_INFORMATION ProcessInfo = { 0 };

	ZwQuerySystemInformation(SystemProcessInformation, NULL, NULL, &Size);
	Buffer = ExAllocatePoolWithTag(NonPagedPool, Size, 'YRXL');

	if (Buffer == nullptr) {
		return NULL;
	}

	auto ProcessInformation = (PSYSTEM_PROCESS_INFORMATION)Buffer;
	Status = ZwQuerySystemInformation(SystemProcessInformation, ProcessInformation, Size, NULL);

	if (!NT_SUCCESS(Status)) {
		ExFreePoolWithTag(Buffer, 'YRXL');
		return NULL;
	}

	for (;;) {
		if (!RtlCompareUnicodeString(&ProcessInformation->ImageName, &Process, TRUE)) {
			ProcessInfo = ProcessInformation;
			break;
		}
		else if (ProcessInformation->NextEntryOffset) {
			ProcessInformation = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<PUCHAR>(ProcessInformation) + ProcessInformation->NextEntryOffset);
		}
		else {
			break;
		}
	}

	ExFreePoolWithTag(Buffer, 'YRXL');
	return ProcessInfo;
}


NTSTATUS AllocateVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	KAPC_STATE Apc = { 0 };

	KeStackAttachProcess(eProcess, &Apc);
	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &Data->Address, NULL, &Data->Size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	KeUnstackDetachProcess(&Apc);

	return Status;
}


NTSTATUS FreeVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	SIZE_T Size = 0ul;
	KAPC_STATE Apc = { 0 };
	
	KeStackAttachProcess(eProcess, &Apc);
	Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &Data->Address, &Size, MEM_RELEASE);
	KeUnstackDetachProcess(&Apc);

	return Status;
}


NTSTATUS ProtectVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	DWORD OldProtection = NULL;
	KAPC_STATE Apc = { 0 };

	KeStackAttachProcess(eProcess, &Apc);
	Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &Data->Address, &Data->Size, Data->Bytes, &OldProtection);
	KeUnstackDetachProcess(&Apc);

	return Status;
}


PHANDLE_TABLE GetHandleTable(PEPROCESS Process) {
	return *(reinterpret_cast<PHANDLE_TABLE*>(((BYTE*)Process + 0x418)));
}


NTSTATUS InitializeProcess(PPROCESS_DATA Data) {
	auto Status = GetProcessID(Data);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = GetBase(Data);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	GetModuleSize(Data);

	return (Data->ModuleSize != NULL) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}


NTSTATUS OpenProcess(PHANDLE_ELEVATION Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	HANDLE Handle = nullptr;

	if (eProcess == nullptr) {
		return STATUS_UNSUCCESSFUL;
	}

	Status = ObOpenObjectByPointer(
		eProcess,
		NULL,
		nullptr,
		Data->AccessMask,
		*PsProcessType,
		KernelMode,
		&Handle
	);

	*(Data->pHandle) = Handle;

	GlobalHandle = Handle;
	GlobalHandleElevation.pHandle = &GlobalHandle;
	GlobalHandleElevation.ProcessID = Data->ProcessID;
	GlobalHandleElevation.AccessMask = Data->AccessMask;

	ObfDereferenceObject(eProcess);
	return Status;
}


BOOLEAN HandleCallback(PHANDLE_TABLE HandleTable, PHANDLE_TABLE_ENTRY HandleTableEntry, HANDLE Handle, PVOID EnumParameter) {
	BOOLEAN bResult = FALSE;
	ASSERT(EnumParameter);

	if (EnumParameter != nullptr) {
		PHANDLE_ELEVATION Data = reinterpret_cast<PHANDLE_ELEVATION>(EnumParameter);

		if (Handle == Data->Handle) {
			if (ExpIsValidObjectEntry(HandleTableEntry)) {
				HandleTableEntry->GrantedAccessBits = Data->AccessMask;
				bResult = TRUE;
			}
		}
	}

	_InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);

	if (HandleTable != NULL && HandleTable->HandleContentionEvent) {
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
	} return bResult;
}


NTSTATUS ElevateHandle(PHANDLE_ELEVATION Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	auto HandleTable = GetHandleTable(eProcess);
	UNICODE_STRING FunctionName = RTL_CONSTANT_STRING(L"ExEnumHandleTable");
	PVOID pExEnumHandleTable = MmGetSystemRoutineAddress(&FunctionName);

	if (pExEnumHandleTable == nullptr || eProcess == nullptr) {
		return STATUS_NOT_FOUND;
	}

	tExEnumHandleTable ExEnumHandleTable = reinterpret_cast<tExEnumHandleTable>(pExEnumHandleTable);
	BOOLEAN bFound = ExEnumHandleTable(HandleTable, &HandleCallback, Data, NULL);

	if (bFound == FALSE) {
		Status = STATUS_NOT_FOUND;
	} return Status;
}