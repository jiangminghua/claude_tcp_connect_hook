#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <wdm.h>

#define LOG_FILE_PATH   L"\\??\\C:\\WfpDriver.log"
#define LOG_BUFFER_SIZE 512

// ---- Log queue node ----

typedef struct _LOG_ENTRY {
    SLIST_ENTRY ListEntry;
    ULONG Size;
    CHAR Buffer[LOG_BUFFER_SIZE];
} LOG_ENTRY, *PLOG_ENTRY;

// ---- Globals ----

static HANDLE       g_LogFileHandle   = nullptr;
static PETHREAD     g_LogThread       = nullptr;
static KEVENT       g_LogEvent;          // wake writer thread (auto-reset)
static KEVENT       g_LogStopEvent;      // tell writer thread to exit (manual-reset)
static SLIST_HEADER g_LogQueue;          // lock-free LIFO queue
static volatile LONG g_LogInitialized = FALSE;

// ---- Reverse SLIST chain (LIFO -> FIFO) ----

static PSLIST_ENTRY ReverseSList(PSLIST_ENTRY head)
{
    PSLIST_ENTRY prev = nullptr;
    while (head) {
        PSLIST_ENTRY next = head->Next;
        head->Next = prev;
        prev = head;
        head = next;
    }
    return prev;
}

// ---- Write all entries in a chain to file ----

static void FlushChainToFile(PSLIST_ENTRY head)
{
    while (head) {
        PLOG_ENTRY logEntry = CONTAINING_RECORD(head, LOG_ENTRY, ListEntry);
        head = head->Next;

        if (g_LogFileHandle) {
            LARGE_INTEGER byteOffset = {};
            IO_STATUS_BLOCK ioStatus;
            ZwWriteFile(g_LogFileHandle, nullptr, nullptr, nullptr,
                        &ioStatus, logEntry->Buffer, logEntry->Size,
                        &byteOffset, nullptr);
        }

        ExFreePoolWithTag(logEntry, 'goLW');
    }
}

// ---- Flush: atomically grab all entries, reverse, write in order ----

static void FlushLogQueue()
{
    PSLIST_ENTRY chain = ExInterlockedFlushSList(&g_LogQueue);
    if (chain) {
        chain = ReverseSList(chain);
        FlushChainToFile(chain);
    }
}

// ---- Writer thread ----

static void LogWriterThread(_In_ PVOID /*Context*/)
{
    PVOID waitObjects[2];
    waitObjects[0] = &g_LogStopEvent;   // index 0 = stop
    waitObjects[1] = &g_LogEvent;       // index 1 = new log

    for (;;) {
        NTSTATUS waitStatus = KeWaitForMultipleObjects(
            2, waitObjects, WaitAny,
            Executive, KernelMode, FALSE, nullptr, nullptr);

        // Drain entire queue in FIFO order
        FlushLogQueue();

        if (waitStatus == STATUS_WAIT_0) {
            // Stop signaled - do a final drain to catch stragglers
            FlushLogQueue();
            break;
        }
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

// ---- Init / Cleanup ----

NTSTATUS LogInit()
{
    UNICODE_STRING fileName;
    OBJECT_ATTRIBUTES objAttributes;
    IO_STATUS_BLOCK ioStatus;

    RtlInitUnicodeString(&fileName, LOG_FILE_PATH);
    InitializeObjectAttributes(&objAttributes, &fileName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);

    NTSTATUS status = ZwCreateFile(&g_LogFileHandle,
                                   FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE,
                                   &objAttributes, &ioStatus, nullptr,
                                   FILE_ATTRIBUTE_NORMAL,
                                   FILE_SHARE_READ,
                                   FILE_OVERWRITE_IF,
                                   FILE_SYNCHRONOUS_IO_NONALERT,
                                   nullptr, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ExInitializeSListHead(&g_LogQueue);
    KeInitializeEvent(&g_LogEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_LogStopEvent, NotificationEvent, FALSE);

    OBJECT_ATTRIBUTES threadAttr;
    HANDLE threadHandle = nullptr;
    InitializeObjectAttributes(&threadAttr, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS,
                                  &threadAttr, nullptr, nullptr,
                                  LogWriterThread, nullptr);
    if (!NT_SUCCESS(status)) {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = nullptr;
        return status;
    }

    ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS,
                              *PsThreadType, KernelMode,
                              reinterpret_cast<PVOID*>(&g_LogThread), nullptr);
    ZwClose(threadHandle);

    InterlockedExchange(&g_LogInitialized, TRUE);
    return STATUS_SUCCESS;
}

void LogCleanup()
{
    if (!InterlockedExchange(&g_LogInitialized, FALSE)) {
        return;
    }

    // Signal writer thread to stop and wait
    KeSetEvent(&g_LogStopEvent, IO_NO_INCREMENT, FALSE);
    if (g_LogThread) {
        KeWaitForSingleObject(g_LogThread, Executive, KernelMode, FALSE, nullptr);
        ObDereferenceObject(g_LogThread);
        g_LogThread = nullptr;
    }

    // Free any remaining entries (should be none after thread drained)
    PSLIST_ENTRY chain = ExInterlockedFlushSList(&g_LogQueue);
    while (chain) {
        PLOG_ENTRY logEntry = CONTAINING_RECORD(chain, LOG_ENTRY, ListEntry);
        chain = chain->Next;
        ExFreePoolWithTag(logEntry, 'goLW');
    }

    if (g_LogFileHandle) {
        ZwClose(g_LogFileHandle);
        g_LogFileHandle = nullptr;
    }
}

// ---- LogPrint (callable from any thread, any IRQL) ----

void LogPrintImpl(_In_ PCCHAR func, _In_ int line, _In_ PCCHAR format, ...)
{
    if (!g_LogInitialized) {
        return;
    }

    PLOG_ENTRY logEntry = (PLOG_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(LOG_ENTRY), 'goLW');
    if (!logEntry) {
        return;
    }

    // Timestamp
    LARGE_INTEGER systemTime, localTime;
    TIME_FIELDS tf;
    KeQuerySystemTime(&systemTime);
    ExSystemTimeToLocalTime(&systemTime, &localTime);
    RtlTimeToTimeFields(&localTime, &tf);

    // Format: [HH:MM:SS.mmm] Func:Line message\n
    size_t prefixLen = 0;
    RtlStringCbPrintfA(logEntry->Buffer, sizeof(logEntry->Buffer) / 2,
        "[%02u:%02u:%02u.%03u] %s:%d ",
        tf.Hour, tf.Minute, tf.Second, tf.Milliseconds,
        func, line);
    RtlStringCbLengthA(logEntry->Buffer, sizeof(logEntry->Buffer) / 2, &prefixLen);

    va_list args;
    va_start(args, format);
    RtlStringCbVPrintfA(logEntry->Buffer + prefixLen,
                         sizeof(logEntry->Buffer) - prefixLen - 2,
                         format, args);
    va_end(args);

    size_t totalLen = 0;
    RtlStringCbLengthA(logEntry->Buffer, sizeof(logEntry->Buffer) - 2, &totalLen);
    logEntry->Buffer[totalLen] = '\n';
    totalLen++;
    logEntry->Size = (ULONG)totalLen;

    // Push into lock-free queue and wake writer
    ExInterlockedPushEntrySList(&g_LogQueue, &logEntry->ListEntry, nullptr);
    KeSetEvent(&g_LogEvent, IO_NO_INCREMENT, FALSE);
}
