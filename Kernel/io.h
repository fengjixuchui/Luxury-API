#pragma once
#include "includes.h"
#include "functions.h"


#define IO_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C0, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_BASE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C1, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_COPY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C2, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_INIT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C3, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C4, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C5, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_FREE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C6, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_OPEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C7, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IO_ELEVATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02C8, METHOD_BUFFERED, FILE_ANY_ACCESS)


NTSTATUS Reception(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = NULL;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	auto Status		 = STATUS_INVALID_DEVICE_REQUEST;
	auto Stack		 = IoGetCurrentIrpStackLocation(Irp);
	auto IoBuffer	 = Irp->AssociatedIrp.SystemBuffer;
	auto ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
	auto InputSize	 = Stack->Parameters.DeviceIoControl.InputBufferLength;
	auto OutputSize	 = Stack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (ControlCode) {
		case IO_COPY: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = CopyProcessMemory(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			} else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_BASE: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = GetBase(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			} else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_PID: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = GetProcessID(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_INIT: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = InitializeProcess(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_ALLOC: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = AllocateVirtualMemory(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_PROTECT: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = ProtectVirtualMemory(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_FREE: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = FreeVirtualMemory(reinterpret_cast<PPROCESS_DATA>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_OPEN: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = OpenProcess(reinterpret_cast<PHANDLE_ELEVATION>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		case IO_ELEVATE: {
			if (InputSize >= sizeof(PROCESS_DATA) && IoBuffer) {
				Status = ElevateHandle(reinterpret_cast<PHANDLE_ELEVATION>(IoBuffer));
			}
			else {
				Status = STATUS_INFO_LENGTH_MISMATCH;
			}
		} break;

		default: {
			Status = STATUS_INVALID_PARAMETER;
		} break;
	}

	if (Status == STATUS_SUCCESS) {
		Irp->IoStatus.Information = OutputSize;
	} else {
		Irp->IoStatus.Information = 0;
	}

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}