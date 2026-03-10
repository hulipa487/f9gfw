const std = @import("std");
const winsock_mod = @import("winsock.zig");
const shared = @import("shared");

const packet_mod = shared.packet;
const IPv4Header = packet_mod.IPv4Header;
const TCPHeader = packet_mod.TCPHeader;

/// WinDivert user-mode packet capture library bindings
/// See: https://www.reqrypt.org/windivert.html
/// Loaded dynamically at runtime
pub const WinDivert = struct {
    pub const HANDLE = ?*anyopaque;
    pub const UINT8 = u8;
    pub const UINT16 = u16;
    pub const UINT32 = u32;
    pub const INT16 = i16;
    pub const INT64 = i64;
    pub const UINT64 = u64;
    pub const BOOL = i32;

    // WinDivert layers
    pub const LAYER_NETWORK = 0;
    pub const LAYER_NETWORK_FORWARD = 1;
    pub const LAYER_SOCKET = 4;

    // Flags
    pub const FLAG_NONE = 0;
    pub const FLAG_RECV_ONLY = 1;
    pub const FLAG_SEND_ONLY = 2;
    pub const FLAG_NO_INSTALL = 4;
    pub const FLAG_RECV_FROM = 8;
    pub const FLAG_SEND_TO = 16;

    // Address structure
    pub const ADDR = extern struct {
        IfIdx: UINT32,
        SubIfIdx: UINT32,
        Layer: UINT8,
        Flags: UINT8,
        Protocol: UINT8,
        Reserved1: UINT8,
        Reserved2: UINT16,
        Timestamp: INT64,
        Value: UINT64,
        Reserved3: UINT64,
    };

    /// Load WinDivert.dll dynamically
    pub fn loadModule() !void {
        if (windivert_module_loaded) return;

        const kernel32 = std.os.windows.kernel32;

        // Try to load WinDivert.dll
        const module_name = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, "WinDivert.dll");
        defer std.heap.page_allocator.free(module_name);

        windivert_module_handle = kernel32.LoadLibraryW(module_name.ptr);
        if (windivert_module_handle == null) {
            const err = kernel32.GetLastError();
            std.log.err("Failed to load WinDivert.dll: error {}", .{err});
            return error.WinDivertNotFound;
        }

        // Load function pointers (GetProcAddress uses ANSI strings)
        windivert_open_fn = @ptrCast(@alignCast(kernel32.GetProcAddress(windivert_module_handle.?, "WinDivertOpenW")));
        windivert_recv_fn = @ptrCast(@alignCast(kernel32.GetProcAddress(windivert_module_handle.?, "WinDivertRecv")));
        windivert_send_fn = @ptrCast(@alignCast(kernel32.GetProcAddress(windivert_module_handle.?, "WinDivertSend")));
        windivert_close_fn = @ptrCast(@alignCast(kernel32.GetProcAddress(windivert_module_handle.?, "WinDivertClose")));

        if (windivert_open_fn == null or windivert_recv_fn == null or
            windivert_send_fn == null or windivert_close_fn == null)
        {
            std.log.err("Failed to load WinDivert functions", .{});
            return error.WinDivertFunctionNotFound;
        }

        windivert_module_loaded = true;
    }

    /// Initialize WinDivert filter
    pub fn open(filter: []const u8, layer: UINT8, priority: INT16, flags: UINT64) !WinDivertHandle {
        try loadModule();

        var handle: HANDLE = null;

        // Convert filter string to null-terminated UTF-16
        const filter_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(std.heap.page_allocator, filter);
        defer std.heap.page_allocator.free(filter_utf16);

        const result = windivert_open_fn.?(
            filter_utf16.ptr,
            layer,
            priority,
            flags,
            &handle,
        );

        if (result == 0 or handle == null) {
            const err = std.os.windows.kernel32.GetLastError();
            std.log.err("WinDivertOpen failed: error {}", .{err});
            return error.WinDivertOpenFailed;
        }

        return .{ .handle = handle.? };
    }

    pub fn unloadModule() void {
        if (windivert_module_handle) |h| {
            std.os.windows.kernel32.FreeLibrary(h);
            windivert_module_handle = null;
            windivert_module_loaded = false;
        }
    }
};

// Module-level variables for dynamic loading
var windivert_module_loaded: bool = false;
var windivert_module_handle: ?std.os.windows.HMODULE = null;

// Function pointer types - using Windows x86_64 calling convention
const WinapiCC = std.builtin.CallingConvention{ .x86_64_win = .{} };

pub const WinDivertOpenWFn = *const fn (
    filter: [*:0]const u16,
    layer: WinDivert.UINT8,
    priority: WinDivert.INT16,
    flags: WinDivert.UINT64,
    handle: *WinDivert.HANDLE,
) callconv(WinapiCC) WinDivert.BOOL;

pub const WinDivertRecvFn = *const fn (
    handle: WinDivert.HANDLE,
    packet: [*]u8,
    packet_len: WinDivert.UINT32,
    read_len: *WinDivert.UINT32,
    addr: ?*WinDivert.ADDR,
) callconv(WinapiCC) WinDivert.BOOL;

pub const WinDivertSendFn = *const fn (
    handle: WinDivert.HANDLE,
    packet: [*]const u8,
    packet_len: WinDivert.UINT32,
    write_len: *WinDivert.UINT32,
    addr: ?*const WinDivert.ADDR,
) callconv(WinapiCC) WinDivert.BOOL;

pub const WinDivertCloseFn = *const fn (
    handle: WinDivert.HANDLE,
) callconv(WinapiCC) WinDivert.BOOL;

var windivert_open_fn: ?WinDivertOpenWFn = null;
var windivert_recv_fn: ?WinDivertRecvFn = null;
var windivert_send_fn: ?WinDivertSendFn = null;
var windivert_close_fn: ?WinDivertCloseFn = null;

/// WinDivert handle wrapper
pub const WinDivertHandle = struct {
    handle: WinDivert.HANDLE,

    pub fn deinit(self: *WinDivertHandle) void {
        if (windivert_close_fn) |fn_ptr| {
            _ = fn_ptr(self.handle);
        }
    }

    /// Receive a packet
    pub fn recv(self: *WinDivertHandle, packet: []u8, addr: *WinDivert.ADDR) !usize {
        var packet_len: WinDivert.UINT32 = 0;

        if (windivert_recv_fn) |fn_ptr| {
            const result = fn_ptr(
                self.handle,
                packet.ptr,
                @intCast(packet.len),
                &packet_len,
                addr,
            );

            if (result == 0) {
                const err = std.os.windows.kernel32.GetLastError();
                std.log.warn("WinDivert recv error code: {}", .{err});
                return error.WinDivertRecvFailed;
            }
        } else {
            return error.WinDivertNotLoaded;
        }

        return packet_len;
    }

    /// Send a packet
    pub fn send(self: *WinDivertHandle, packet: []const u8, addr: *const WinDivert.ADDR) !usize {
        var packet_len: WinDivert.UINT32 = 0;

        if (windivert_send_fn) |fn_ptr| {
            const result = fn_ptr(
                self.handle,
                packet.ptr,
                @intCast(packet.len),
                &packet_len,
                addr,
            );

            if (result == 0) {
                const err = std.os.windows.kernel32.GetLastError();
                std.log.warn("WinDivert send error code: {}", .{err});
                return error.WinDivertSendFailed;
            }
        } else {
            return error.WinDivertNotLoaded;
        }

        return packet_len;
    }
};

/// Packet capture callback type for WinDivert
pub const PacketCaptureCallback = *const fn (
    packet: []const u8,
    addr: *const WinDivert.ADDR,
    user_data: *anyopaque,
) void;

/// Capture context for background thread
pub const CaptureContext = struct {
    handle: *WinDivertHandle,
    callback: PacketCaptureCallback,
    user_data: *anyopaque,
    running: *std.atomic.Value(bool),
    allocator: std.mem.Allocator,
};

/// Packet capturer using WinDivert
/// Captures outbound TCP packets matching a filter
pub const PacketCapturer = struct {
    handle: WinDivertHandle,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),

    pub const Config = struct {
        /// Destination IP to filter on
        dst_ip: [4]u8,
        /// Destination port to filter on
        dst_port: u16,
        /// Protocol (TCP=6)
        protocol: u8 = 6,
        /// Priority (higher = first in chain)
        priority: i16 = 0,
    };

    /// Open WinDivert filter for capturing outbound TCP packets
    pub fn init(allocator: std.mem.Allocator, config: Config) !PacketCapturer {
        // Build WinDivert filter string
        // Filter: outbound TCP packets to specific IP:port
        const filter_str = try std.fmt.allocPrint(
            allocator,
            "outbound and tcp and ip.DstAddr={d}.{d}.{d}.{d} and tcp.DstPort={d}",
            .{ config.dst_ip[0], config.dst_ip[1], config.dst_ip[2], config.dst_ip[3], config.dst_port },
        );
        defer allocator.free(filter_str);

        std.log.info("Opening WinDivert filter: {s}", .{filter_str});

        const handle = try WinDivert.open(
            filter_str,
            WinDivert.LAYER_NETWORK,
            config.priority,
            WinDivert.FLAG_NONE,
        );

        return .{
            .handle = handle,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *PacketCapturer) void {
        self.stop();
        self.handle.deinit();
    }

    /// Start capturing packets in a background thread
    pub fn start(self: *PacketCapturer, callback: PacketCaptureCallback, user_data: *anyopaque) !void {
        self.running.store(true, .monotonic);

        const ctx = try self.allocator.create(CaptureContext);
        ctx.* = .{
            .handle = &self.handle,
            .callback = callback,
            .user_data = user_data,
            .running = &self.running,
            .allocator = self.allocator,
        };

        const thread = try std.Thread.spawn(.{}, captureThread, .{ctx});
        thread.detach();
    }

    /// Stop capturing
    pub fn stop(self: *PacketCapturer) void {
        self.running.store(false, .monotonic);
    }

    /// Background capture thread
    fn captureThread(ctx: *CaptureContext) void {
        defer ctx.allocator.destroy(ctx);

        var packet_buf: [65535]u8 = undefined;
        var addr: WinDivert.ADDR = undefined;

        while (ctx.running.load(.monotonic)) {
            // Receive packet
            const len = ctx.handle.recv(&packet_buf, &addr) catch |err| {
                std.log.warn("WinDivert recv error: {}", .{err});
                std.os.windows.kernel32.Sleep(10);
                continue;
            };

            if (len > 0) {
                // Call user callback with packet data
                ctx.callback(packet_buf[0..len], &addr, ctx.user_data);
            }
        }
    }
};
