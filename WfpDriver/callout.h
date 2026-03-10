#pragma once

#pragma warning(push)
#pragma warning(disable:4201)  // nameless struct/union

extern "C" {
#include <ntddk.h>
#define NDIS_WDM 1
#define NDIS680 1
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
}

#pragma warning(pop)

// IOCTL codes
#define WFPDRIVER_DEVICE_TYPE 0x8000
#define IOCTL_SET_PROXY_PID     CTL_CODE(WFPDRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_ORIGINAL_DEST CTL_CODE(WFPDRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Max connections tracked
constexpr int MAX_CONNECTION_ENTRIES = 4096;

// Connection mapping entry
struct CONNECTION_ENTRY {
    UINT32 originalIp;      // Original destination IP (network byte order)
    UINT16 originalPort;    // Original destination port (network byte order)
    UINT16 localPort;       // Redirected local source port
    UINT64 processId;       // Process that initiated the connection
    UINT32 remoteIp;        // Remote destination IP (network byte order)
    UINT32 remotePort;      // Remote destination port (network byte order)
    BOOLEAN inUse;
};

// IOCTL structures (must match ProxyClient packing)
#pragma pack(push, 1)
struct QUERY_ORIGINAL_DEST {
    UINT16 localPort;
};

struct ORIGINAL_DEST_INFO {
    UINT32 originalIp;
    UINT16 originalPort;
};
#pragma pack(pop)

// Proxy settings
constexpr UINT32 PROXY_LOCAL_IP_NBO   = 0x0100007F;  // 127.0.0.1 in network byte order (for SOCKADDR)
constexpr UINT16 PROXY_LOCAL_PORT     = 10800;
constexpr UINT32 PROXY_SERVER_IP_HBO  = 0x2B864D23;  // 43.134.77.35 in host byte order (for WFP comparison)

// Global data
extern CONNECTION_ENTRY g_ConnectionTable[];
extern KSPIN_LOCK g_ConnectionTableLock;
extern UINT64 g_ProxyPid;
extern UINT32 g_CalloutId;
extern UINT64 g_FilterId;
extern HANDLE g_EngineHandle;
extern HANDLE g_RedirectHandle;

// Callout functions
NTSTATUS RegisterWfpCallout(_In_ PDEVICE_OBJECT deviceObject);
void UnregisterWfpCallout();

// Connection table functions
void AddConnectionEntry(UINT16 localPort, UINT32 originalIp, UINT16 originalPort, UINT64 processId, UINT32 remoteIp, UINT32 remotePort);
BOOLEAN GetOriginalDest(UINT16 localPort, UINT32* originalIp, UINT16* originalPort);
void RemoveConnectionEntry(UINT16 localPort);
void RemoveConnectionEntryByOriginal(UINT32 originalIp, UINT16 originalPort);

// Logging functions
NTSTATUS LogInit();
void LogCleanup();
void LogPrintImpl(_In_ PCCHAR func, _In_ int line, _In_ PCCHAR format, ...);

#define LogPrint(fmt, ...) LogPrintImpl(__FUNCTION__, __LINE__, fmt, ##__VA_ARGS__)
