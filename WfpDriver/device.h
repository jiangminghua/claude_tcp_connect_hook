#pragma once

extern "C" {
#include <ntddk.h>
}

constexpr auto DEVICE_NAME  = L"\\Device\\WfpTcpProxy";
constexpr auto SYMLINK_NAME = L"\\DosDevices\\WfpTcpProxy";

NTSTATUS DeviceCreate(_In_ PDRIVER_OBJECT driverObject, _Out_ PDEVICE_OBJECT* deviceObject);
void DeviceCleanup(_In_ PDEVICE_OBJECT deviceObject);
