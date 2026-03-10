#include "callout.h"
#include "device.h"

static NTSTATUS DeviceIoControlHandler(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);

    auto irpSp = IoGetCurrentIrpStackLocation(irp);
    auto ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    auto inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    auto outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    auto buffer = irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    switch (ioControlCode) {
    case IOCTL_SET_PROXY_PID:
        if (inputLen < sizeof(UINT64) || buffer == nullptr) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        g_ProxyPid = *static_cast<UINT64*>(buffer);
        LogPrint("[WfpDriver] Proxy PID set to %llu", g_ProxyPid);
        break;

    case IOCTL_GET_ORIGINAL_DEST:
        if (inputLen < sizeof(QUERY_ORIGINAL_DEST) || buffer == nullptr) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLen < sizeof(ORIGINAL_DEST_INFO)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            auto query = static_cast<QUERY_ORIGINAL_DEST*>(buffer);
            auto result = static_cast<ORIGINAL_DEST_INFO*>(buffer);
            UINT32 origIp;
            UINT16 origPort;

            if (GetOriginalDest(query->localPort, &origIp, &origPort)) {
                result->originalIp = origIp;
                result->originalPort = origPort;
                bytesReturned = sizeof(ORIGINAL_DEST_INFO);
            } else {
                status = STATUS_NOT_FOUND;
            }
        }
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static NTSTATUS DeviceCreateClose(
    _In_ PDEVICE_OBJECT deviceObject,
    _In_ PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS DeviceCreate(_In_ PDRIVER_OBJECT driverObject, _Out_ PDEVICE_OBJECT* deviceObject)
{
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);

    auto status = IoCreateDevice(
        driverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        deviceObject);

    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] IoCreateDevice failed: 0x%08X", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] IoCreateSymbolicLink failed: 0x%08X", status);
        IoDeleteDevice(*deviceObject);
        *deviceObject = nullptr;
        return status;
    }

    driverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;

    LogPrint("[WfpDriver] Device created successfully");
    return STATUS_SUCCESS;
}

void DeviceCleanup(_In_ PDEVICE_OBJECT deviceObject)
{
    UNICODE_STRING symlinkName;
    RtlInitUnicodeString(&symlinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (deviceObject) {
        IoDeleteDevice(deviceObject);
    }
}
