#include "callout.h"
#include "device.h"

static PDEVICE_OBJECT g_DeviceObject = nullptr;

static void DriverUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    LogPrint("[WfpDriver] Unloading driver...");

    UnregisterWfpCallout();
    DeviceCleanup(g_DeviceObject);

    LogPrint("[WfpDriver] Driver unloaded");
    LogCleanup();
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    UNREFERENCED_PARAMETER(registryPath);

    LogPrint("[WfpDriver] DriverEntry");

    driverObject->DriverUnload = DriverUnload;

    auto status = LogInit();
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] LogInit failed: 0x%08X", status);
        return status;
    }

    status = DeviceCreate(driverObject, &g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] DeviceCreate failed: 0x%08X", status);
        return status;
    }

    status = RegisterWfpCallout(g_DeviceObject);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] RegisterWfpCallout failed: 0x%08X", status);
        DeviceCleanup(g_DeviceObject);
        return status;
    }

    LogPrint("[WfpDriver] Driver loaded successfully");
    return STATUS_SUCCESS;
}
