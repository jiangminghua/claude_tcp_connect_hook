#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <cstdio>
#include <cstdlib>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

#define LISTEN_PORT 19000
#define BUFFER_SIZE 65536

static void XorEncrypt(char* data, int len)
{
    for (int i = 0; i < len; i++) {
        data[i] ^= 0xcc;
    }
}

// Receive encrypted from client, decrypt, send plain to target
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
            if (ret <= 0) {
                return;
            }
            sent += ret;
        }
        ZeroMemory(buffer, sizeof(buffer));
    }
    Sleep(5300);
    shutdown(to, SD_SEND);
	closesocket(to);
}

// Receive plain from target, encrypt, send to client
static void RelayPlainToEncrypted(SOCKET from, SOCKET to, int* keyOffset)
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
            if (ret <= 0) {
                return;
            }
            sent += ret;
        }
        ZeroMemory(buffer, sizeof(buffer));
    }
	Sleep(5300);  // slight delay to ensure all data is sent before closing
    shutdown(to, SD_SEND);
	closesocket(to);
}

static void HandleClient(SOCKET clientSock)
{
    // Read 6-byte header: [4 bytes IP][2 bytes port] (XOR encrypted)
    unsigned char header[6];
    int totalRead = 0;
    while (totalRead < 6) {
        int ret = recv(clientSock, (char*)header + totalRead, 6 - totalRead, 0);
        if (ret <= 0) {
            printf("[!] Failed to read header from client\n");
            closesocket(clientSock);
            return;
        }
        totalRead += ret;
    }

    // Decrypt header
    int recvKeyOffset = 0;
    XorEncrypt((char*)header, 6);

    // Parse original destination (IP and port are already in network byte order)
    struct in_addr destAddr;
    USHORT destPortNbo;
    memcpy(&destAddr.s_addr, header, 4);
    memcpy(&destPortNbo, header + 4, 2);

    char destIpStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &destAddr, destIpStr, sizeof(destIpStr));
    printf("[+] Connecting to original target: %s:%u\n", destIpStr, ntohs(destPortNbo));

    // Connect to original target
    SOCKET targetSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (targetSock == INVALID_SOCKET) {
        printf("[!] Failed to create target socket\n");
        closesocket(clientSock);
        return;
    }

    struct sockaddr_in targetAddr = {};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_addr = destAddr;
    targetAddr.sin_port = destPortNbo;  // already network byte order

    if (connect(targetSock, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) == SOCKET_ERROR) {
        printf("[!] Failed to connect to %s:%u (error %d)\n", destIpStr, ntohs(destPortNbo), WSAGetLastError());
        closesocket(targetSock);
        closesocket(clientSock);
        return;
    }

    printf("[+] Connected to %s:%u, starting relay\n", destIpStr, ntohs(destPortNbo));

    // Bidirectional relay with XOR encryption
    // recvKeyOffset continues from header decryption (already at 6)
    int sendKeyOffset = 0;
    std::thread t1(RelayEncryptedToPlain, clientSock, targetSock, &recvKeyOffset);
    std::thread t2(RelayPlainToEncrypted, targetSock, clientSock, &sendKeyOffset);

    t1.join();
    t2.join();
    
    printf("two thread close, Connection to %s:%u closed\n", destIpStr, ntohs(destPortNbo));
    //closesocket(targetSock);
    //closesocket(clientSock);
}

int main()
{
    printf("=== TCP Proxy Server ===\n");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[!] WSAStartup failed\n");
        return 1;
    }

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSock == INVALID_SOCKET) {
        printf("[!] socket() failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    int opt = 1;
    setsockopt(listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    struct sockaddr_in listenAddr = {};
    listenAddr.sin_family = AF_INET;
    listenAddr.sin_addr.s_addr = INADDR_ANY;
    listenAddr.sin_port = htons(LISTEN_PORT);

    if (bind(listenSock, (struct sockaddr*)&listenAddr, sizeof(listenAddr)) == SOCKET_ERROR) {
        printf("[!] bind() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    if (listen(listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("[!] listen() failed: %d\n", WSAGetLastError());
        closesocket(listenSock);
        WSACleanup();
        return 1;
    }

    while (true) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        SOCKET clientSock = accept(listenSock, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSock == INVALID_SOCKET) {
            printf("[!] accept() failed: %d\n", WSAGetLastError());
            continue;
        }

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
        printf("[+] Client connected from %s:%u\n", clientIp, ntohs(clientAddr.sin_port));

        std::thread(HandleClient, clientSock).detach();
    }

    closesocket(listenSock);
    WSACleanup();
    return 0;
}
