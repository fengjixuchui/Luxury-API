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
		Status = MmCopyVirtualMemory(eProcess, 
					     Data->Address, 
					     IoGetCurrentProcess(), 
					     Data->Data, 
					     Data->Size, 
					     KernelMode, 
					     &Data->Bytes);
	}
	else {
		Status = MmCopyVirtualMemory(IoGetCurrentProcess(), 
					     Data->Data, 
					     eProcess, 
					     Data->Address, 
					     Data->Size, 
					     KernelMode, 
					     &Data->Bytes);
	}

	ObfDereferenceObject(eProcess);
	return Status;
}


NTSTATUS AllocateVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	KAPC_STATE Apc = { 0 };

	KeStackAttachProcess(eProcess, &Apc);
	
	Status = ZwAllocateVirtualMemory(ZwCurrentProcess(), 
					 &Data->Address, 
					 NULL, 
					 &Data->Size, 
					 MEM_COMMIT | MEM_RESERVE, 
					 PAGE_EXECUTE_READWRITE);
	
	KeUnstackDetachProcess(&Apc);

	return Status;
}


NTSTATUS FreeVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	SIZE_T Size = 0ul;
	KAPC_STATE Apc = { 0 };
	
	KeStackAttachProcess(eProcess, &Apc);
	
	Status = ZwFreeVirtualMemory(ZwCurrentProcess(), 
				     &Data->Address, 
				     &Size, 
				     MEM_RELEASE);
	
	KeUnstackDetachProcess(&Apc);

	return Status;
}


NTSTATUS ProtectVirtualMemory(PPROCESS_DATA Data) {
	auto Status = STATUS_SUCCESS;
	auto eProcess = GetProcess(Data->ProcessID);
	DWORD OldProtection = NULL;
	KAPC_STATE Apc = { 0 };

	KeStackAttachProcess(eProcess, &Apc);
	
	Status = ZwProtectVirtualMemory(ZwCurrentProcess(), 
					&Data->Address,
					&Data->Size, 
					Data->Bytes, 
					&OldProtection);
	
	KeUnstackDetachProcess(&Apc);

	return Status;
}
