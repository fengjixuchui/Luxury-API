#include "includes.h"
#include "io.h"


NTSTATUS MapDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	auto Status = STATUS_SUCCESS;
	PDEVICE_OBJECT Device = nullptr;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\zwpsnt");
	UNICODE_STRING SymbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\zwpsnt");

	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &Device);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	Status = IoCreateSymbolicLink(&SymbolicLink, &DeviceName);

	if (!NT_SUCCESS(Status)) {
		IoDeleteDevice(Device);
		return Status;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = Reception;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = Reception;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	DriverObject->DriverUnload = nullptr;

	Device->Flags |= DO_DIRECT_IO;
	Device->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	return IoCreateDriver(nullptr, &MapDriver);
}