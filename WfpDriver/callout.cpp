#include <initguid.h>
#include "callout.h"

// {B16B0A6E-2B2A-41A3-8B39-BD3FFC855FF8} - Callout GUID
DEFINE_GUID(WFP_CALLOUT_GUID,
    0xb16b0a6e, 0x2b2a, 0x41a3, 0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf8);

// {C26B0A6E-3B2A-41A3-8B39-BD3FFC855FF9} - Sublayer GUID
DEFINE_GUID(WFP_SUBLAYER_GUID,
    0xc26b0a6e, 0x3b2a, 0x41a3, 0x8b, 0x39, 0xbd, 0x3f, 0xfc, 0x85, 0x5f, 0xf9);

// Globals
CONNECTION_ENTRY g_ConnectionTable[MAX_CONNECTION_ENTRIES] = {};
KSPIN_LOCK g_ConnectionTableLock;
UINT64 g_ProxyPid = 0;
UINT32 g_CalloutId = 0;
UINT64 g_FilterId = 0;
UINT64 g_UdpBlockDnsFilterId = 0;  // Unused, kept for binary compat
UINT64 g_UdpBlockQuicFilterId = 0;
UINT64 g_Ipv6BlockFilterId = 0;
HANDLE g_EngineHandle = nullptr;
HANDLE g_RedirectHandle = nullptr;

// ---- Connection table management ----

void AddConnectionEntry(UINT16 localPort, UINT32 originalIp, UINT16 originalPort, UINT64 processId, UINT32 remoteIp, UINT32 remotePort)
{
    LogPrint("[WfpDriver] AddConnectionEntry: localPort=%u, originalIp=%u.%u.%u.%u, originalPort=%u, processId=%llu, remoteIp=%u.%u.%u.%u, remotePort=%u",
        localPort,
        (originalIp >> 24) & 0xFF, (originalIp >> 16) & 0xFF, (originalIp >> 8) & 0xFF, (originalIp >> 0) & 0xFF,
        originalPort,
        processId,
        (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, (remoteIp >> 0) & 0xFF,
        remotePort);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ConnectionTableLock, &lockHandle);

    for (int i = 0; i < MAX_CONNECTION_ENTRIES; i++) {
        if (!g_ConnectionTable[i].inUse) {
            g_ConnectionTable[i].originalIp = originalIp;
            g_ConnectionTable[i].originalPort = originalPort;
            g_ConnectionTable[i].localPort = localPort;
            g_ConnectionTable[i].processId = processId;
            g_ConnectionTable[i].remoteIp = remoteIp;
            g_ConnectionTable[i].remotePort = remotePort;
            g_ConnectionTable[i].inUse = TRUE;
            LogPrint("[WfpDriver] AddConnectionEntry: Entry added at index %d", i);
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

BOOLEAN GetOriginalDest(UINT16 localPort, UINT32* originalIp, UINT16* originalPort)
{
    LogPrint("[WfpDriver] GetOriginalDest: localPort=%u", localPort);

    BOOLEAN found = FALSE;
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ConnectionTableLock, &lockHandle);

    for (int i = 0; i < MAX_CONNECTION_ENTRIES; i++) {
        if (g_ConnectionTable[i].inUse && g_ConnectionTable[i].localPort == localPort) {
            *originalIp = g_ConnectionTable[i].originalIp;
            *originalPort = g_ConnectionTable[i].originalPort;
            g_ConnectionTable[i].inUse = FALSE;
            found = TRUE;
            LogPrint("[WfpDriver] GetOriginalDest: Found entry at index %d, originalIp=%u.%u.%u.%u, originalPort=%u",
                i,
                (*originalIp >> 24) & 0xFF, (*originalIp >> 16) & 0xFF, (*originalIp >> 8) & 0xFF, (*originalIp >> 0) & 0xFF,
                *originalPort);
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return found;
}

void RemoveConnectionEntry(UINT16 localPort)
{
    LogPrint("[WfpDriver] RemoveConnectionEntry: localPort=%u", localPort);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ConnectionTableLock, &lockHandle);

    for (int i = 0; i < MAX_CONNECTION_ENTRIES; i++) {
        if (g_ConnectionTable[i].inUse && g_ConnectionTable[i].localPort == localPort) {
            g_ConnectionTable[i].inUse = FALSE;
            LogPrint("[WfpDriver] RemoveConnectionEntry: Removed entry at index %d", i);
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

void RemoveConnectionEntryByOriginal(UINT32 originalIp, UINT16 originalPort)
{
    LogPrint("[WfpDriver] RemoveConnectionEntryByOriginal: originalIp=%u.%u.%u.%u, originalPort=%u",
        (originalIp >> 24) & 0xFF, (originalIp >> 16) & 0xFF, (originalIp >> 8) & 0xFF, (originalIp >> 0) & 0xFF,
        originalPort);

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_ConnectionTableLock, &lockHandle);

    for (int i = 0; i < MAX_CONNECTION_ENTRIES; i++) {
        if (g_ConnectionTable[i].inUse && 
            g_ConnectionTable[i].originalIp == originalIp && 
            g_ConnectionTable[i].originalPort == originalPort) {
            g_ConnectionTable[i].inUse = FALSE;
            LogPrint("[WfpDriver] RemoveConnectionEntryByOriginal: Removed entry at index %d", i);
            break;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

// ---- WFP Classify callback ----

static void NTAPI ClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ void* layerData,
    _In_opt_ const void* classifyContext,
    _In_ const FWPS_FILTER3* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    LogPrint("[WfpDriver] ClassifyFn called");

    if (!(classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        LogPrint("[WfpDriver] ClassifyFn: No write rights");
        return;
    }

    LogPrint("[WfpDriver] ClassifyFn: Has write rights");

    // Acquire classify handle from classifyContext (required for ALE_CONNECT_REDIRECT)
    UINT64 classifyHandle = 0;
    NTSTATUS handleStatus = FwpsAcquireClassifyHandle0(
        const_cast<void*>(classifyContext), 0, &classifyHandle);
    if (!NT_SUCCESS(handleStatus)) {
        LogPrint("[WfpDriver] ClassifyFn: FwpsAcquireClassifyHandle0 failed: 0x%08X", handleStatus);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    // Get process ID
    UINT64 processId = 0;
    if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
        processId = inMetaValues->processId;
        LogPrint("[WfpDriver] ClassifyFn: Process ID = %llu", processId);
    } else {
        LogPrint("[WfpDriver] ClassifyFn: No process ID available");
    }

    // Get remote IP and port from fixed values (all in host byte order)
    auto remoteIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    auto remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;
    auto localPort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_LOCAL_PORT].value.uint16;

    LogPrint("[WfpDriver] PID=%llu %u.%u.%u.%u:%u localPort=%u",
        processId,
        (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
        remotePort, localPort);

    // Skip proxy process itself to avoid redirect loop
    if (g_ProxyPid != 0 && processId == g_ProxyPid) {
        LogPrint("[WfpDriver] SKIP proxy PID=%llu %u.%u.%u.%u:%u",
            processId,
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        goto release_handle;
    }

    // Skip localhost connections (127.x.x.x)
    if ((remoteIp >> 24) == 127) {
        LogPrint("[WfpDriver] SKIP localhost %u.%u.%u.%u:%u",
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        goto release_handle;
    }

    // Skip connections to proxy server itself
    if (remoteIp == PROXY_SERVER_IP_HBO) {
        LogPrint("[WfpDriver] SKIP proxy server %u.%u.%u.%u:%u",
            (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
            remotePort);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        goto release_handle;
    }

    // Perform redirect
    {
        FWPS_CONNECT_REQUEST0* connectRequest = nullptr;
        NTSTATUS status = FwpsAcquireWritableLayerDataPointer0(
            classifyHandle,
            filter->filterId,
            0,
            reinterpret_cast<PVOID*>(&connectRequest),
            classifyOut);

        if (!NT_SUCCESS(status) || connectRequest == nullptr) {
            LogPrint("[WfpDriver] FAIL redirect %u.%u.%u.%u:%u status=0x%08X",
                (remoteIp >> 24) & 0xFF, (remoteIp >> 16) & 0xFF, (remoteIp >> 8) & 0xFF, remoteIp & 0xFF,
                remotePort, status);
            classifyOut->actionType = FWP_ACTION_PERMIT;
            goto release_handle;
        }

        // Read original destination from SOCKADDR (guaranteed network byte order)
        auto origAddrIn = reinterpret_cast<SOCKADDR_IN*>(&connectRequest->remoteAddressAndPort);
        UINT32 origIpNbo = origAddrIn->sin_addr.S_un.S_addr;   // network byte order
        UINT16 origPortNbo = origAddrIn->sin_port;              // network byte order

        // Store in connection table as network byte order (ProxyClient uses directly)
        AddConnectionEntry(localPort, origIpNbo, origPortNbo, processId, remoteIp, remotePort);

        // Log original destination
        LogPrint("[WfpDriver] Original dest: %u.%u.%u.%u:%u",
            origIpNbo & 0xFF, (origIpNbo >> 8) & 0xFF, (origIpNbo >> 16) & 0xFF, (origIpNbo >> 24) & 0xFF,
            RtlUshortByteSwap(origPortNbo));

        // Redirect to local proxy
        origAddrIn->sin_addr.S_un.S_addr = PROXY_LOCAL_IP_NBO;
        origAddrIn->sin_port = RtlUshortByteSwap(PROXY_LOCAL_PORT);

        // Set redirect handle and target PID (required for Windows 8+)
        connectRequest->localRedirectTargetPID = static_cast<DWORD>(g_ProxyPid);
        connectRequest->localRedirectHandle = g_RedirectHandle;

        FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);

        classifyOut->actionType = FWP_ACTION_PERMIT;
        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;

        LogPrint("[WfpDriver] OK redirect PID=%llu -> 127.0.0.1:%u (localPort=%u)",
            processId, PROXY_LOCAL_PORT, localPort);
    }

release_handle:
    FwpsReleaseClassifyHandle0(classifyHandle);
}

// ---- Notify callback ----

static NTSTATUS NTAPI NotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER3* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    LogPrint("[WfpDriver] NotifyFn called, type=%d", notifyType);
    return STATUS_SUCCESS;
}

// ---- Flow delete callback ----

static void NTAPI FlowDeleteFn(
    _In_ UINT16 layerId,
    _In_ UINT32 calloutId,
    _In_ UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    LogPrint("[WfpDriver] FlowDeleteFn called, flowContext=%llu, calloutId=%u, layerId=%u", flowContext, calloutId, layerId);
}

// ---- Registration ----

NTSTATUS RegisterWfpCallout(_In_ PDEVICE_OBJECT deviceObject)
{
    LogPrint("[WfpDriver] RegisterWfpCallout: Starting registration");

    KeInitializeSpinLock(&g_ConnectionTableLock);

    // Create redirect handle (required for ALE_CONNECT_REDIRECT on Win8+)
    auto status = FwpsRedirectHandleCreate0(&WFP_CALLOUT_GUID, 0, &g_RedirectHandle);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] RegisterWfpCallout: FwpsRedirectHandleCreate0 failed: 0x%08X", status);
        return status;
    }
    LogPrint("[WfpDriver] RegisterWfpCallout: Redirect handle created: %p", g_RedirectHandle);

    // Open WFP engine
    LogPrint("[WfpDriver] RegisterWfpCallout: Opening WFP engine");
    status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] RegisterWfpCallout: FwpmEngineOpen failed: 0x%08X", status);
        return status;
    }
    LogPrint("[WfpDriver] RegisterWfpCallout: WFP engine opened, handle=%p", g_EngineHandle);

    // Begin transaction
    LogPrint("[WfpDriver] RegisterWfpCallout: Beginning transaction");
    status = FwpmTransactionBegin0(g_EngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] RegisterWfpCallout: FwpmTransactionBegin failed: 0x%08X", status);
        goto cleanup_engine;
    }
    LogPrint("[WfpDriver] RegisterWfpCallout: Transaction started");

    {
        // Add sublayer
        LogPrint("[WfpDriver] RegisterWfpCallout: Adding sublayer");
        FWPM_SUBLAYER0 sublayer = {};
        sublayer.subLayerKey = WFP_SUBLAYER_GUID;
        sublayer.displayData.name = const_cast<wchar_t*>(L"WfpTcpProxy Sublayer");
        sublayer.weight = 0xFFFF;

        status = FwpmSubLayerAdd0(g_EngineHandle, &sublayer, nullptr);
        if (!NT_SUCCESS(status)) {
            LogPrint("[WfpDriver] RegisterWfpCallout: FwpmSubLayerAdd failed: 0x%08X", status);
            goto abort_transaction;
        }
        LogPrint("[WfpDriver] RegisterWfpCallout: Sublayer added");

        // Register callout with FWPS (kernel)
        LogPrint("[WfpDriver] RegisterWfpCallout: Registering callout with FWPS");
        FWPS_CALLOUT3 sCallout = {};
        sCallout.calloutKey = WFP_CALLOUT_GUID;
        sCallout.classifyFn = ClassifyFn;
        sCallout.notifyFn = NotifyFn;
        sCallout.flowDeleteFn = FlowDeleteFn;

        status = FwpsCalloutRegister3(deviceObject, &sCallout, &g_CalloutId);
        if (!NT_SUCCESS(status)) {
            LogPrint("[WfpDriver] RegisterWfpCallout: FwpsCalloutRegister failed: 0x%08X", status);
            goto abort_transaction;
        }
        LogPrint("[WfpDriver] RegisterWfpCallout: Callout registered, calloutId=%u", g_CalloutId);

        // Add callout to FWPM (engine)
        LogPrint("[WfpDriver] RegisterWfpCallout: Adding callout to FWPM");
        FWPM_CALLOUT0 mCallout = {};
        mCallout.calloutKey = WFP_CALLOUT_GUID;
        mCallout.displayData.name = const_cast<wchar_t*>(L"WfpTcpProxy Connect Redirect Callout");
        mCallout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;

        status = FwpmCalloutAdd0(g_EngineHandle, &mCallout, nullptr, nullptr);
        if (!NT_SUCCESS(status)) {
            LogPrint("[WfpDriver] RegisterWfpCallout: FwpmCalloutAdd failed: 0x%08X", status);
            goto abort_transaction;
        }
        LogPrint("[WfpDriver] RegisterWfpCallout: Callout added to FWPM");

        // Add filter (TCP only to avoid breaking ICMP/UDP)
        LogPrint("[WfpDriver] RegisterWfpCallout: Adding filter");
        FWPM_FILTER_CONDITION0 filterCondition = {};
        filterCondition.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        filterCondition.matchType = FWP_MATCH_EQUAL;
        filterCondition.conditionValue.type = FWP_UINT8;
        filterCondition.conditionValue.uint8 = IPPROTO_TCP;

        FWPM_FILTER0 wfpFilter = {};
        wfpFilter.displayData.name = const_cast<wchar_t*>(L"WfpTcpProxy Connect Redirect Filter");
        wfpFilter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
        wfpFilter.subLayerKey = WFP_SUBLAYER_GUID;
        wfpFilter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
        wfpFilter.action.calloutKey = WFP_CALLOUT_GUID;
        wfpFilter.filterCondition = &filterCondition;
        wfpFilter.numFilterConditions = 1;
        wfpFilter.weight.type = FWP_UINT8;
        wfpFilter.weight.uint8 = 0xF;

        status = FwpmFilterAdd0(g_EngineHandle, &wfpFilter, nullptr, &g_FilterId);
        if (!NT_SUCCESS(status)) {
            LogPrint("[WfpDriver] RegisterWfpCallout: FwpmFilterAdd failed: 0x%08X", status);
            goto abort_transaction;
        }
        LogPrint("[WfpDriver] RegisterWfpCallout: Filter added, filterId=%llu", g_FilterId);

        // ---- Block UDP 443 (QUIC/HTTP3) to force TCP fallback ----
        LogPrint("[WfpDriver] RegisterWfpCallout: Adding UDP QUIC block filter");
        {
            FWPM_FILTER_CONDITION0 udpQuicConditions[2] = {};

            // Condition 1: UDP protocol
            udpQuicConditions[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
            udpQuicConditions[0].matchType = FWP_MATCH_EQUAL;
            udpQuicConditions[0].conditionValue.type = FWP_UINT8;
            udpQuicConditions[0].conditionValue.uint8 = IPPROTO_UDP;

            // Condition 2: Remote port 443
            udpQuicConditions[1].fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
            udpQuicConditions[1].matchType = FWP_MATCH_EQUAL;
            udpQuicConditions[1].conditionValue.type = FWP_UINT16;
            udpQuicConditions[1].conditionValue.uint16 = 443;

            FWPM_FILTER0 udpQuicFilter = {};
            udpQuicFilter.displayData.name = const_cast<wchar_t*>(L"WfpTcpProxy Block UDP QUIC");
            udpQuicFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
            udpQuicFilter.subLayerKey = WFP_SUBLAYER_GUID;
            udpQuicFilter.action.type = FWP_ACTION_BLOCK;
            udpQuicFilter.filterCondition = udpQuicConditions;
            udpQuicFilter.numFilterConditions = 2;
            udpQuicFilter.weight.type = FWP_UINT8;
            udpQuicFilter.weight.uint8 = 0xF;

            status = FwpmFilterAdd0(g_EngineHandle, &udpQuicFilter, nullptr, &g_UdpBlockQuicFilterId);
            if (!NT_SUCCESS(status)) {
                LogPrint("[WfpDriver] RegisterWfpCallout: UDP QUIC block filter failed: 0x%08X", status);
                goto abort_transaction;
            }
            LogPrint("[WfpDriver] RegisterWfpCallout: UDP QUIC block filter added, filterId=%llu", g_UdpBlockQuicFilterId);
        }

        // ---- Block all IPv6 outbound connections to prevent IPv6 leaks ----
        LogPrint("[WfpDriver] RegisterWfpCallout: Adding IPv6 block filter");
        {
            FWPM_FILTER0 ipv6Filter = {};
            ipv6Filter.displayData.name = const_cast<wchar_t*>(L"WfpTcpProxy Block IPv6");
            ipv6Filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            ipv6Filter.subLayerKey = WFP_SUBLAYER_GUID;
            ipv6Filter.action.type = FWP_ACTION_BLOCK;
            ipv6Filter.filterCondition = nullptr;  // No conditions = match all IPv6
            ipv6Filter.numFilterConditions = 0;
            ipv6Filter.weight.type = FWP_UINT8;
            ipv6Filter.weight.uint8 = 0xF;

            status = FwpmFilterAdd0(g_EngineHandle, &ipv6Filter, nullptr, &g_Ipv6BlockFilterId);
            if (!NT_SUCCESS(status)) {
                LogPrint("[WfpDriver] RegisterWfpCallout: IPv6 block filter failed: 0x%08X", status);
                goto abort_transaction;
            }
            LogPrint("[WfpDriver] RegisterWfpCallout: IPv6 block filter added, filterId=%llu", g_Ipv6BlockFilterId);
        }
    }

    // Commit transaction
    LogPrint("[WfpDriver] RegisterWfpCallout: Committing transaction");
    status = FwpmTransactionCommit0(g_EngineHandle);
    if (!NT_SUCCESS(status)) {
        LogPrint("[WfpDriver] RegisterWfpCallout: FwpmTransactionCommit failed: 0x%08X", status);
        goto cleanup_engine;
    }
    LogPrint("[WfpDriver] RegisterWfpCallout: Transaction committed");

    LogPrint("[WfpDriver] RegisterWfpCallout: WFP callout registered successfully");
    return STATUS_SUCCESS;

abort_transaction:
    LogPrint("[WfpDriver] RegisterWfpCallout: Aborting transaction");
    FwpmTransactionAbort0(g_EngineHandle);
cleanup_engine:
    LogPrint("[WfpDriver] RegisterWfpCallout: Closing WFP engine");
    FwpmEngineClose0(g_EngineHandle);
    g_EngineHandle = nullptr;
    return status;
}

void UnregisterWfpCallout()
{
    LogPrint("[WfpDriver] UnregisterWfpCallout: Starting unregistration");

    if (g_EngineHandle) {
        if (g_Ipv6BlockFilterId) {
            LogPrint("[WfpDriver] UnregisterWfpCallout: Deleting IPv6 block filter %llu", g_Ipv6BlockFilterId);
            FwpmFilterDeleteById0(g_EngineHandle, g_Ipv6BlockFilterId);
            g_Ipv6BlockFilterId = 0;
        }
        if (g_UdpBlockQuicFilterId) {
            LogPrint("[WfpDriver] UnregisterWfpCallout: Deleting UDP QUIC block filter %llu", g_UdpBlockQuicFilterId);
            FwpmFilterDeleteById0(g_EngineHandle, g_UdpBlockQuicFilterId);
            g_UdpBlockQuicFilterId = 0;
        }
        if (g_FilterId) {
            LogPrint("[WfpDriver] UnregisterWfpCallout: Deleting filter %llu", g_FilterId);
            FwpmFilterDeleteById0(g_EngineHandle, g_FilterId);
            g_FilterId = 0;
        }
        LogPrint("[WfpDriver] UnregisterWfpCallout: Deleting sublayer");
        FwpmSubLayerDeleteByKey0(g_EngineHandle, &WFP_SUBLAYER_GUID);
        LogPrint("[WfpDriver] UnregisterWfpCallout: Deleting callout");
        FwpmCalloutDeleteByKey0(g_EngineHandle, &WFP_CALLOUT_GUID);
        LogPrint("[WfpDriver] UnregisterWfpCallout: Closing WFP engine");
        FwpmEngineClose0(g_EngineHandle);
        g_EngineHandle = nullptr;
    }

    if (g_CalloutId) {
        LogPrint("[WfpDriver] UnregisterWfpCallout: Unregistering callout %u", g_CalloutId);
        FwpsCalloutUnregisterById0(g_CalloutId);
        g_CalloutId = 0;
    }

    if (g_RedirectHandle) {
        FwpsRedirectHandleDestroy0(g_RedirectHandle);
        g_RedirectHandle = nullptr;
        LogPrint("[WfpDriver] UnregisterWfpCallout: Redirect handle destroyed");
    }

    LogPrint("[WfpDriver] UnregisterWfpCallout: WFP callout unregistered");
}
