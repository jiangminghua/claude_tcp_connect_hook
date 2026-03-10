#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <winioctl.h>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// Must match driver definitions
#define WFPDRIVER_DEVICE_TYPE 0x8000
#define IOCTL_SET_PROXY_PID     CTL_CODE(WFPDRIVER_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_ORIGINAL_DEST CTL_CODE(WFPDRIVER_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 1)
typedef struct _QUERY_ORIGINAL_DEST {
    UINT16 localPort;
} QUERY_ORIGINAL_DEST;

typedef struct _ORIGINAL_DEST_INFO {
    UINT32 originalIp;
    UINT16 originalPort;
} ORIGINAL_DEST_INFO;
#pragma pack(pop)

#define LOCAL_PROXY_PORT    10800
#define REMOTE_SERVER_IP    "43.134.77.35"
#define REMOTE_SERVER_PORT  19000
#define BUFFER_SIZE         65536
#define DRIVER_SERVICE_NAME L"WfpDriver"

static void XorEncrypt(char* data, int len)
{
    for (int i = 0; i < len; i++) {
        data[i] ^= 0xcc;
    }
}

static HANDLE g_DriverHandle = INVALID_HANDLE_VALUE;

// ---- Driver management ----

static bool InstallDriver(const wchar_t* driverPath)
{
    SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) {
        printf("[!] OpenSCManager failed: %lu\n", GetLastError());
        return false;
    }

    // Try to open existing service first
    SC_HANDLE service = OpenServiceW(scManager, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service) {
        // Service exists, try to start it
        printf("[*] Driver service already exists\n");
    } else {
        // Create new service
        service = CreateServiceW(
            scManager,
            DRIVER_SERVICE_NAME,
            L"WFP TCP Proxy Driver",
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            driverPath,
            NULL, NULL, NULL, NULL, NULL);

        if (!service) {
            printf("[!] CreateService failed: %lu\n", GetLastError());
            CloseServiceHandle(scManager);
            return false;
        }
        printf("[+] Driver service created\n");
    }

    // Start the service
    if (!StartServiceW(service, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[!] StartService failed: %lu\n", err);
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            return false;
        }
        printf("[*] Driver already running\n");
    } else {
        printf("[+] Driver started\n");
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

static void StopDriver()
{
    SC_HANDLE scManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scManager) return;

    SC_HANDLE service = OpenServiceW(scManager, DRIVER_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (service) {
        SERVICE_STATUS status;
        ControlService(service, SERVICE_CONTROL_STOP, &status);
        DeleteService(service);
        CloseServiceHandle(service);
        printf("[+] Driver stopped and service deleted\n");
    }

    CloseServiceHandle(scManager);
}

static bool OpenDriverDevice()
{
    g_DriverHandle = CreateFileW(
        L"\\\\.\\WfpTcpProxy",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_DriverHandle == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open driver device: %lu\n", GetLastError());
        return false;
    }
    return true;
}

static bool SetProxyPid()
{
    UINT64 pid = (UINT64)GetCurrentProcessId();
    DWORD bytesReturned;

    if (!DeviceIoControl(g_DriverHandle, IOCTL_SET_PROXY_PID,
        &pid, sizeof(pid), NULL, 0, &bytesReturned, NULL)) {
        printf("[!] Failed to set proxy PID: %lu\n", GetLastError());
        return false;
    }
    printf("[+] Proxy PID set to %llu\n", pid);
    return true;
}

static bool QueryOriginalDest(UINT16 localPort, UINT32* origIp, UINT16* origPort)
{
    QUERY_ORIGINAL_DEST query;
    query.localPort = localPort;

    ORIGINAL_DEST_INFO result;
    DWORD bytesReturned;

    if (!DeviceIoControl(g_DriverHandle, IOCTL_GET_ORIGINAL_DEST,
        &query, sizeof(query), &result, sizeof(result), &bytesReturned, NULL)) {
        return false;
    }

    *origIp = result.originalIp;
    *origPort = result.originalPort;
    return true;
}

// ---- Data relay ----

// Plain relay (app <-> local proxy, no encryption)
static void RelayPlainToEncrypted(SOCKET from, SOCKET to, int* keyOffset)
{
    char buffer[BUFFER_SIZE];
    int bytes;
    ZeroMemory(buffer, sizeof(buffer));
    while ((bytes = recv(from, buffer, BUFFER_SIZE, 0)) > 0) {        
        XorEncrypt(buffer, bytes); 
        //printf("%d,%s\n", __LINE__, buffer);
        int sent = 0;
        while (sent < bytes) {
            int ret = send(to, buffer + sent, bytes - sent, 0);
            if (ret <= 0) return;
            sent += ret;
        }
        ZeroMemory(buffer, sizeof(buffer));
    }
    Sleep(5300);
    shutdown(to, SD_SEND);
	closesocket(to);
}

static void RelayEncryptedToPlain(SOCKET from, SOCKET to, int* keyOffset)
{
    char buffer[BUFFER_SIZE];
    int bytes;
    ZeroMemory(buffer, sizeof(buffer));
    while ((bytes = recv(from, buffer, BUFFER_SIZE, 0)) > 0) {        
        //printf("%d,%s\n", __LINE__, buffer); 
        XorEncrypt(buffer, bytes);
        int sent = 0;
        while (sent < bytes) {
            int ret = send(to, buffer + sent, bytes - sent, 0);
            if (ret <= 0) return;
            sent += ret;
        }
        ZeroMemory(buffer, sizeof(buffer));
    }
    Sleep(5300);
    shutdown(to, SD_SEND);
    closesocket(to);
}

// ---- Handle redirected connection ----

static void HandleClient(SOCKET clientSock, struct sockaddr_in clientAddr)
{
    UINT16 clientPort = ntohs(clientAddr.sin_port);

    char clientIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &clientAddr.sin_addr, clientIpStr, sizeof(clientIpStr));
    printf("[+] HandleClient: %s:%u\n", clientIpStr, clientPort);

    // Query original destination from driver
    UINT32 origIp;
    UINT16 origPort;

    // Retry a few times as the mapping may not be immediately available
    bool found = false;
    for (int i = 0; i < 10; i++) {
        if (QueryOriginalDest(clientPort, &origIp, &origPort)) {
            found = true;
            break;
        }
        Sleep(10);
    }

    if (!found) {
        printf("[!] Could not find original dest for local port %u\n", clientPort);
        closesocket(clientSock);
        return;
    }

    // origIp and origPort from driver are already in network byte order
    struct in_addr addr;
    addr.s_addr = origIp;
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
    printf("[+] Port %u -> original dest %s:%u\n", clientPort, ipStr, ntohs(origPort));

    // Connect to remote proxy server
    SOCKET remoteSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (remoteSock == INVALID_SOCKET) {
        printf("[!] socket() failed for remote: %d\n", WSAGetLastError());
        closesocket(clientSock);
        return;
    }

    struct sockaddr_in remoteAddr = {};
    remoteAddr.sin_family = AF_INET;
    inet_pton(AF_INET, REMOTE_SERVER_IP, &remoteAddr.sin_addr);
    remoteAddr.sin_port = htons(REMOTE_SERVER_PORT);

    if (connect(remoteSock, (struct sockaddr*)&remoteAddr, sizeof(remoteAddr)) == SOCKET_ERROR) {
        printf("[!] Failed to connect to remote server: %d\n", WSAGetLastError());
        closesocket(remoteSock);
        closesocket(clientSock);
        return;
    }

    // Send 6-byte header: [4 bytes IP][2 bytes port] already in network byte order (XOR encrypted)
    unsigned char header[6];
    memcpy(header, &origIp, 4);
    memcpy(header + 4, &origPort, 2);

    // XOR encrypt header
    int sendKeyOffset = 0;
    XorEncrypt((char*)header, 6);

    int sent = 0;
    while (sent < 6) {
        int ret = send(remoteSock, (const char*)header + sent, 6 - sent, 0);
        if (ret <= 0) {
            printf("[!] Failed to send header to remote\n");
            closesocket(remoteSock);
            closesocket(clientSock);
            return;
        }
        sent += ret;
    }

    printf("[+] Relaying: client <-> remote server <-> %s:%u\n", ipStr, origPort);

    // Bidirectional relay with XOR encryption
    // sendKeyOffset continues from header (already at 6)
    int recvKeyOffset = 0;
    std::thread t1(RelayPlainToEncrypted, clientSock, remoteSock, &sendKeyOffset);
    std::thread t2(RelayEncryptedToPlain, remoteSock, clientSock, &recvKeyOffset);

    t1.join();
    t2.join();

    printf("two thread close, Connection to %s:%u closed\n", ipStr, origPort);
    //closesocket(remoteSock);
    //closesocket(clientSock);
}

// ---- Main ----

int main(int argc, char* argv[])
{
    printf("=== TCP Proxy Client ===\n");

    // Determine driver path
    wchar_t driverPath[MAX_PATH];
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    // Default: look for WfpDriver.sys next to the executable
    std::wstring exeDir(exePath);
    size_t lastSlash = exeDir.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos) {
        exeDir = exeDir.substr(0, lastSlash + 1);
    }
    swprintf_s(driverPath, MAX_PATH, L"%sWfpDriver.sys", exeDir.c_str());

    // Allow specifying driver path as argument
    if (argc > 1) {
        MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, driverPath, MAX_PATH);
    }

    printf("[*] Driver path: %ls\n", driverPath);

    // Check if driver file exists
    if (GetFileAttributesW(driverPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] Driver file not found: %ls\n", driverPath);
        printf("[!] Please place WfpDriver.sys next to this executable or specify path as argument\n");
        return 1;
    }

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[!] WSAStartup failed\n");
        return 1;
    }

    // Install and start driver
    if (!InstallDriver(driverPath)) {
        printf("[!] Failed to install/start driver\n");
        WSACleanup();
        return 1;
    }

    // Open driver device
    if (!OpenDriverDevice()) {
        StopDriver();
        WSACleanup();
        return 1;
    }

    // Set proxy PID to exclude our own connections
    if (!SetProxyPid()) {
        CloseHandle(g_DriverHandle);
        StopDriver();
        WSACleanup();
        return 1;
    }

    // Create listening socket
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        CloseHandle(g_DriverHandle);
        StopDriver();
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in listenAddr = {};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listenAddr.sin_port = htons(LOCAL_PROXY_PORT);

    if (bind(listenSock, (struct sockaddr*)&listenAddr, sizeof(listenAddr)) == SOCKET_ERROR) {
        printf("[!] bind() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        CloseHandle(g_DriverHandle);
        StopDriver();
        WSACleanup();
        return 1;
    }

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("[!] listen() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        CloseHandle(g_DriverHandle);
        StopDriver();
        WSACleanup();
        return 1;
    }

    printf("[+] Local proxy listening on 127.0.0.1:%d\n", LOCAL_PROXY_PORT);
    printf("[+] Remote server: %s:%d\n", REMOTE_SERVER_IP, REMOTE_SERVER_PORT);
    printf("[*] Press Ctrl+C to stop\n\n");

    // Set console control handler for cleanup
    SetConsoleCtrlHandler([](DWORD ctrlType) -> BOOL {
        if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
            printf("\n[*] Shutting down...\n");
            if (g_DriverHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(g_DriverHandle);
            }
            StopDriver();
            WSACleanup();
            ExitProcess(0);
        }
        return FALSE;
    }, TRUE);

    // Accept loop
    while (true) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock == INVALID_SOCKET) {
            printf("[!] accept() failed: %d\n", WSAGetLastError());
            continue;
        }
        printf("HandleClient %s:%d\n", __FILE__, __LINE__);
        std::thread(HandleClient, clientSock, clientAddr).detach();
    }

    closesocket(listenSock);
    CloseHandle(g_DriverHandle);
    StopDriver();
    WSACleanup();
    return 0;
}
