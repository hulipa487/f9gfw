const std = @import("std");

/// Windows Filtering Platform (WFP) bindings for packet capture
pub const WFP = struct {
    pub const HANDLE = ?*anyopaque;
    pub const UINT32 = u32;
    pub const UINT64 = u64;
    pub const BOOL = i32;

    // WFP constants
    pub const FWPM_SESSION_FLAG_DYNAMIC: UINT32 = 0x00000001;

    // Layer IDs
    pub const FWPM_LAYER_ALE_AUTH_CONNECT_V4: GUID = .{
        .Data1 = 0xc38d57d1,
        .Data2 = 0x05a7,
        .Data3 = 0x4c42,
        .Data4 = .{ 0x85, 0x23, 0x4b, 0xd6, 0x74, 0x78, 0x09, 0x48 },
    };

    pub const FWPM_LAYER_OUTBOUND_TRANSPORT_V4: GUID = .{
        .Data1 = 0x04a3596e,
        .Data2 = 0x0a10,
        .Data3 = 0x4bcd,
        .Data4 = .{ 0x9d, 0x3b, 0x7c, 0x5c, 0x17, 0x0e, 0x6e, 0x2a },
    };

    // Action types
    pub const FWP_ACTION_BLOCK: UINT32 = 0x00000001;
    pub const FWP_ACTION_PERMIT: UINT32 = 0x00000002;
    pub const FWP_ACTION_CALLOUT_INSPECTION: UINT32 = 0x00000004;
    pub const FWP_ACTION_CALLOUT_TERMINATING: UINT32 = 0x00000008;

    // Callout conditions
    pub const FWPM_CONDITION_IP_LOCAL_PORT: GUID = .{
        .Data1 = 0x0c1ba1af,
        .Data2 = 0x5765,
        .Data3 = 0x453f,
        .Data4 = .{ 0xaf, 0x22, 0xa8, 0xf7, 0x94, 0x38, 0x35, 0x1c },
    };

    pub const FWPM_CONDITION_IP_REMOTE_PORT: GUID = .{
        .Data1 = 0xc35a604d,
        .Data2 = 0xd22b,
        .Data3 = 0x4e1d,
        .Data4 = .{ 0xa1, 0x3e, 0x79, 0x0b, 0x44, 0x85, 0x61, 0x50 },
    };

    pub const FWPM_CONDITION_IP_REMOTE_ADDRESS: GUID = .{
        .Data1 = 0xb235ae9a,
        .Data2 = 0x1d0b,
        .Data3 = 0x4524,
        .Data4 = .{ 0xa8, 0x90, 0x15, 0x34, 0x6c, 0x51, 0xf7, 0xf8 },
    };

    // Data types
    pub const FWP_UINT8: UINT32 = 0;
    pub const FWP_UINT16: UINT32 = 1;
    pub const FWP_UINT32: UINT32 = 2;
    pub const FWP_UINT64: UINT32 = 3;
    pub const FWP_BYTE_ARRAY16_TYPE: UINT32 = 7;

    // Condition operators
    pub const FWP_MATCH_EQUAL: UINT32 = 0;
    pub const FWP_MATCH_GREATER: UINT32 = 1;
    pub const FWP_MATCH_LESS: UINT32 = 2;
    pub const FWP_MATCH_GREATER_OR_EQUAL: UINT32 = 3;
    pub const FWP_MATCH_LESS_OR_EQUAL: UINT32 = 4;
    pub const FWP_MATCH_RANGE: UINT32 = 5;

    pub const GUID = extern struct {
        Data1: u32,
        Data2: u16,
        Data3: u16,
        Data4: [8]u8,
    };

    pub const FWP_BYTE_ARRAY16 = extern struct {
        byteArray16: [16]u8,
    };

    pub const FWP_VALUE0 = extern struct {
        type: UINT32,
        value: extern union {
            uint8: u8,
            uint16: u16,
            uint32: u32,
            uint64: u64,
            byteArray16: *FWP_BYTE_ARRAY16,
        },
    };

    pub const FWPM_FILTER_CONDITION0 = extern struct {
        fieldKey: GUID,
        matchType: UINT32,
        conditionValue: FWP_VALUE0,
    };

    pub const FWPM_ACTION0 = extern struct {
        @"type": UINT32,
        action: extern union {
            filterType: GUID,
            calloutKey: GUID,
        },
    };

    pub const FWPM_FILTER0 = extern struct {
        filterKey: GUID,
        displayData: FWPM_DISPLAY_DATA0,
        flags: UINT32,
        providerKey: ?*GUID,
        providerData: FWP_BYTE_BLOB,
        weight: FWP_VALUE0,
        subLayerKey: GUID,
        layerKey: GUID,
        action: FWPM_ACTION0,
        numFilterConditions: UINT32,
        filterCondition: ?*FWPM_FILTER_CONDITION0,
        effectiveWeight: FWP_VALUE0,
    };

    pub const FWPM_DISPLAY_DATA0 = extern struct {
        name: ?[*:0]const u16,
        description: ?[*:0]const u16,
    };

    pub const FWP_BYTE_BLOB = extern struct {
        size: UINT32,
        data: ?*u8,
    };

    pub const FWPM_SESSION0 = extern struct {
        displayData: FWPM_DISPLAY_DATA0,
        flags: UINT32,
        txnWaitTimeoutInMSec: UINT32,
        processId: UINT32,
        sid: ?*anyopaque,
        username: ?[*:0]const u16,
        kernelMode: BOOL,
    };

    pub const FWPM_CALLOUT0 = extern struct {
        calloutKey: GUID,
        displayData: FWPM_DISPLAY_DATA0,
        flags: UINT32,
        providerKey: ?*GUID,
        providerData: FWP_BYTE_BLOB,
        applicableLayer: GUID,
    };

    /// WFP Engine handle
    engine: HANDLE,

    /// Initialize WFP engine
    pub fn init() !WFP {
        var session: FWPM_SESSION0 = std.mem.zeroes(FWPM_SESSION0);
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        var engine: HANDLE = null;
        const result = FwpmEngineOpen0(
            null,
            0x0202,
            null,
            &session,
            &engine,
        );

        if (result != 0) {
            return error.FwpmEngineOpenFailed;
        }

        return .{ .engine = engine };
    }

    pub fn deinit(self: *WFP) void {
        if (self.engine) |engine| {
            _ = FwpmEngineClose0(engine);
        }
    }

    /// Add a filter to block TCP traffic to a specific port (for testing)
    pub fn addBlockFilter(self: *WFP, port: u16) !GUID {
        var filter_key: GUID = undefined;
        std.mem.set(u8, std.mem.asBytes(&filter_key), 0);

        var filter: FWPM_FILTER0 = std.mem.zeroes(FWPM_FILTER0);
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.action.@"type" = FWP_ACTION_BLOCK;

        // Set display name
        const name = std.unicode.utf8ToUtf16LeWithNull(std.heap.page_allocator, "f9gfw block filter") catch unreachable;
        defer std.heap.page_allocator.free(name);
        filter.displayData.name = name.ptr;

        // Add condition for port
        var condition: FWPM_FILTER_CONDITION0 = std.mem.zeroes(FWPM_FILTER_CONDITION0);
        condition.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_UINT16;
        condition.conditionValue.value.uint16 = port;

        filter.numFilterConditions = 1;
        filter.filterCondition = &condition;

        const result = FwpmFilterAdd0(
            self.engine,
            &filter,
            null,
            null,
        );

        if (result != 0) {
            return error.FwpmFilterAddFailed;
        }

        return filter_key;
    }

    /// Remove a filter
    pub fn removeFilter(self: *WFP, filter_key: GUID) !void {
        _ = self;
        _ = filter_key;
        // FwpmFilterDeleteByKey0 would go here
    }

    // WFP function declarations
    extern "fwpuclnt" fn FwpmEngineOpen0(
        serverName: ?[*:0]const u16,
        authnService: UINT32,
        authIdentity: ?*anyopaque,
        session: ?*const FWPM_SESSION0,
        engineHandle: *HANDLE,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmEngineClose0(
        engineHandle: HANDLE,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmFilterAdd0(
        engineHandle: HANDLE,
        filter: *const FWPM_FILTER0,
        sd: ?*anyopaque,
        id: ?*UINT64,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmFilterDeleteByKey0(
        engineHandle: HANDLE,
        key: *const GUID,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmTransactionBegin0(
        engineHandle: HANDLE,
        flags: UINT32,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmTransactionCommit0(
        engineHandle: HANDLE,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmTransactionAbort0(
        engineHandle: HANDLE,
    ) callconv(.win64) UINT32;

    extern "fwpuclnt" fn FwpmCalloutAdd0(
        engineHandle: HANDLE,
        callout: *const FWPM_CALLOUT0,
        sd: ?*anyopaque,
        id: ?*UINT32,
    ) callconv(.win64) UINT32;
};

/// Packet capture callback type
pub const PacketCallback = *const fn (
    src_ip: [4]u8,
    src_port: u16,
    dst_ip: [4]u8,
    dst_port: u16,
    data: []const u8,
) void;

/// Simple packet interceptor using WFP
/// Note: Full WFP callout drivers require kernel-mode components.
/// This implementation provides a simplified user-mode approach.
pub const PacketInterceptor = struct {
    wfp: WFP,

    pub fn init() !PacketInterceptor {
        const wfp = try WFP.init();
        return .{ .wfp = wfp };
    }

    pub fn deinit(self: *PacketInterceptor) void {
        self.wfp.deinit();
    }

    /// Note: Real packet capture requires a kernel-mode callout driver.
    /// For a user-mode solution, consider using WinPcap/Npcap or
    /// implementing a simple TCP proxy instead.
    pub fn startCapture(_: *PacketInterceptor, _: PacketCallback) !void {
        return error.RequiresKernelDriver;
    }
};
