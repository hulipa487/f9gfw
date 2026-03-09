const std = @import("std");

/// Winsock2 wrapper for TCP operations
pub const Winsock = struct {
    pub const SOCKET = usize;
    pub const INVALID_SOCKET: SOCKET = @as(SOCKET, @bitCast(@as(isize, -1)));
    pub const SOCKET_ERROR: isize = -1;

    pub const AF_INET: i32 = 2;
    pub const SOCK_STREAM: i32 = 1;
    pub const SOCK_DGRAM: i32 = 2;
    pub const SOCK_RAW: i32 = 3;
    pub const IPPROTO_TCP: i32 = 6;
    pub const IPPROTO_UDP: i32 = 17;
    pub const IPPROTO_ICMP: i32 = 1;
    pub const IPPROTO_IP: i32 = 0;

    pub const SOL_SOCKET: i32 = 0xFFFF;
    pub const SO_REUSEADDR: i32 = 4;
    pub const SO_LINGER: i32 = 0x80;
    pub const SO_BROADCAST: i32 = 0x20;

    pub const IP_TTL: i32 = 4;
    pub const IP_DONTFRAGMENT: i32 = 14;

    pub const LINGER = extern struct {
        l_onoff: u16,
        l_linger: u16,
    };

    pub const sockaddr_in = extern struct {
        sin_family: u16,
        sin_port: u16,
        sin_addr: u32,
        sin_zero: [8]u8,
    };

    pub const WSAData = extern struct {
        wVersion: u16,
        wHighVersion: u16,
        szDescription: [257:0]u8,
        szSystemStatus: [129:0]u8,
        iMaxSockets: u16,
        iMaxUdpDg: u16,
        lpVendorInfo: ?*anyopaque,
    };

    /// Initialize Winsock
    pub fn init() !void {
        var wsa_data: WSAData = undefined;
        const result = wsa_startup(0x0202, &wsa_data);
        if (result != 0) {
            return error.WSAStartupFailed;
        }
    }

    /// Cleanup Winsock
    pub fn deinit() void {
        _ = wsa_cleanup();
    }

    /// Create a TCP socket
    pub fn socketTcp() !SOCKET {
        const sock = wsa_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            return error.SocketFailed;
        }
        return sock;
    }

    /// Create a UDP socket
    pub fn socketUdp() !SOCKET {
        const sock = wsa_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            return error.SocketFailed;
        }
        return sock;
    }

    /// Create a raw ICMP socket (for receiving ICMP messages)
    pub fn socketIcmp() !SOCKET {
        const sock = wsa_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sock == INVALID_SOCKET) {
            return error.SocketFailed;
        }
        return sock;
    }

    /// Create a raw socket with specified protocol
    pub fn socketRaw(protocol: i32) !SOCKET {
        const sock = wsa_socket(AF_INET, SOCK_RAW, protocol);
        if (sock == INVALID_SOCKET) {
            return error.SocketFailed;
        }
        return sock;
    }

    /// Set socket TTL
    pub fn setTTL(sock: SOCKET, ttl: u8) !void {
        var ttl_val: u32 = ttl;
        const result = wsa_setsockopt(
            sock,
            IPPROTO_IP,
            IP_TTL,
            @ptrCast(&ttl_val),
            @sizeOf(u32),
        );
        if (result == SOCKET_ERROR) {
            return error.SetTTLFailed;
        }
    }

    /// Set abortive close (RST instead of FIN)
    pub fn setAbortiveClose(sock: SOCKET) !void {
        var linger: LINGER = .{
            .l_onoff = 1,
            .l_linger = 0,
        };
        const result = wsa_setsockopt(
            sock,
            SOL_SOCKET,
            SO_LINGER,
            @ptrCast(&linger),
            @sizeOf(LINGER),
        );
        if (result == SOCKET_ERROR) {
            return error.SetLingerFailed;
        }
    }

    /// Connect to a remote address
    pub fn connect(sock: SOCKET, ip: [4]u8, port: u16) !void {
        var addr: sockaddr_in = .{
            .sin_family = AF_INET,
            .sin_port = std.mem.nativeToBig(u16, port),
            .sin_addr = @bitCast(ip),
            .sin_zero = [_]u8{0} ** 8,
        };
        const result = wsa_connect(
            sock,
            @ptrCast(&addr),
            @sizeOf(sockaddr_in),
        );
        if (result == SOCKET_ERROR) {
            const err = wsa_getlasterror();
            if (err == 10060) { // WSAETIMEDOUT
                return error.ConnectionTimedOut;
            }
            return error.ConnectFailed;
        }
    }

    /// Bind to a local address
    pub fn bind(sock: SOCKET, ip: [4]u8, port: u16) !void {
        var addr: sockaddr_in = .{
            .sin_family = AF_INET,
            .sin_port = std.mem.nativeToBig(u16, port),
            .sin_addr = @bitCast(ip),
            .sin_zero = [_]u8{0} ** 8,
        };
        const result = wsa_bind(
            sock,
            @ptrCast(&addr),
            @sizeOf(sockaddr_in),
        );
        if (result == SOCKET_ERROR) {
            return error.BindFailed;
        }
    }

    /// Send data
    pub fn send(sock: SOCKET, data: []const u8) !usize {
        const result = wsa_send(sock, data.ptr, @intCast(data.len), 0);
        if (result == SOCKET_ERROR) {
            return error.SendFailed;
        }
        return @intCast(result);
    }

    /// Receive data
    pub fn recv(sock: SOCKET, buf: []u8) !usize {
        const result = wsa_recv(sock, buf.ptr, @intCast(buf.len), 0);
        if (result == SOCKET_ERROR) {
            return error.RecvFailed;
        }
        if (result == 0) {
            return error.ConnectionClosed;
        }
        return @intCast(result);
    }

    /// Send UDP data
    pub fn sendTo(sock: SOCKET, data: []const u8, ip: [4]u8, port: u16) !usize {
        var addr: sockaddr_in = .{
            .sin_family = AF_INET,
            .sin_port = std.mem.nativeToBig(u16, port),
            .sin_addr = @bitCast(ip),
            .sin_zero = [_]u8{0} ** 8,
        };
        const result = wsa_sendto(
            sock,
            data.ptr,
            @intCast(data.len),
            0,
            @ptrCast(&addr),
            @sizeOf(sockaddr_in),
        );
        if (result == SOCKET_ERROR) {
            return error.SendFailed;
        }
        return @intCast(result);
    }

    /// Close socket
    pub fn close(sock: SOCKET) void {
        _ = wsa_closesocket(sock);
    }

    /// Listen for connections
    pub fn listen(sock: SOCKET, backlog: i32) !void {
        const result = wsa_listen(sock, backlog);
        if (result == SOCKET_ERROR) {
            return error.ListenFailed;
        }
    }

    /// Accept a connection
    pub fn accept(sock: SOCKET, addr: ?*sockaddr_in, addr_len: ?*i32) !SOCKET {
        const client = wsa_accept(sock, @ptrCast(addr), @as(?*i32, @ptrCast(addr_len)));
        if (client == INVALID_SOCKET) {
            return error.AcceptFailed;
        }
        return client;
    }

    /// Receive UDP data
    pub fn recvFrom(sock: SOCKET, buf: []u8, from_ip: *[4]u8, from_port: *u16) !usize {
        var addr: sockaddr_in = undefined;
        var addr_len: i32 = @sizeOf(sockaddr_in);
        const result = wsa_recvfrom(
            sock,
            buf.ptr,
            @intCast(buf.len),
            0,
            @ptrCast(&addr),
            &addr_len,
        );
        if (result == SOCKET_ERROR) {
            return error.RecvFailed;
        }
        from_ip.* = @bitCast(addr.sin_addr);
        from_port.* = std.mem.bigToNative(u16, addr.sin_port);
        return @intCast(result);
    }

    /// Get socket name (local address)
    pub fn getSockName(sock: SOCKET, addr: *sockaddr_in) !void {
        var addr_len: i32 = @sizeOf(sockaddr_in);
        if (wsa_getsockname(sock, @ptrCast(addr), &addr_len) == SOCKET_ERROR) {
            return error.GetSockNameFailed;
        }
    }
};

// Internal setsockopt for reuse address (returns error code, not error union)
pub fn setsockopt_internal(s: Winsock.SOCKET, level: i32, optname: i32, optval: ?*const anyopaque, optlen: i32) i32 {
    return wsa_setsockopt(s, level, optname, optval, optlen);
}

/// TCP connection with TTL control for NAT traversal
pub const TcpTunnel = struct {
    sock: Winsock.SOCKET,
    local_port: u16,
    remote_ip: [4]u8,
    remote_port: u16,

    /// Create a TTL-limited connection (SYN packets expire before reaching destination)
    pub fn initTTLLimited(
        remote_ip: [4]u8,
        remote_port: u16,
        ttl: u8,
    ) !TcpTunnel {
        const sock = try Winsock.socketTcp();
        errdefer Winsock.close(sock);

        // Set TTL
        try Winsock.setTTL(sock, ttl);

        // Bind to any local port
        try Winsock.bind(sock, .{ 0, 0, 0, 0 }, 0);

        // Get assigned local port
        var addr: Winsock.sockaddr_in = undefined;
        var addr_len: i32 = @sizeOf(Winsock.sockaddr_in);
        if (wsa_getsockname(sock, @ptrCast(&addr), &addr_len) == Winsock.SOCKET_ERROR) {
            return error.GetSockNameFailed;
        }
        const local_port = std.mem.bigToNative(u16, addr.sin_port);

        // Try to connect (will fail with TTL limit, that's expected)
        Winsock.connect(sock, remote_ip, remote_port) catch {};

        return .{
            .sock = sock,
            .local_port = local_port,
            .remote_ip = remote_ip,
            .remote_port = remote_port,
        };
    }

    /// Create a normal TCP connection
    pub fn init(remote_ip: [4]u8, remote_port: u16) !TcpTunnel {
        const sock = try Winsock.socketTcp();
        errdefer Winsock.close(sock);

        try Winsock.bind(sock, .{ 0, 0, 0, 0 }, 0);

        var addr: Winsock.sockaddr_in = undefined;
        var addr_len: i32 = @sizeOf(Winsock.sockaddr_in);
        if (wsa_getsockname(sock, @ptrCast(&addr), &addr_len) == Winsock.SOCKET_ERROR) {
            return error.GetSockNameFailed;
        }
        const local_port = std.mem.bigToNative(u16, addr.sin_port);

        try Winsock.connect(sock, remote_ip, remote_port);

        return .{
            .sock = sock,
            .local_port = local_port,
            .remote_ip = remote_ip,
            .remote_port = remote_port,
        };
    }

    pub fn deinit(self: *TcpTunnel) void {
        Winsock.close(self.sock);
    }

    pub fn send(self: *TcpTunnel, data: []const u8) !usize {
        return Winsock.send(self.sock, data);
    }

    pub fn recv(self: *TcpTunnel, buf: []u8) !usize {
        return Winsock.recv(self.sock, buf);
    }

    pub fn getLocalPort(self: *const TcpTunnel) u16 {
        return self.local_port;
    }
};


// Winsock2 function declarations with renamed symbols to avoid conflicts
extern "ws2_32" fn WSAStartup(wVersionRequested: u16, lpWSAData: *Winsock.WSAData) callconv(.c) i32;
extern "ws2_32" fn WSACleanup() callconv(.c) i32;
extern "ws2_32" fn WSAGetLastError() callconv(.c) i32;
extern "ws2_32" fn socket(af: i32, type: i32, protocol: i32) callconv(.c) Winsock.SOCKET;
extern "ws2_32" fn setsockopt(s: Winsock.SOCKET, level: i32, optname: i32, optval: ?*const anyopaque, optlen: i32) callconv(.c) i32;
extern "ws2_32" fn connect(s: Winsock.SOCKET, name: *const anyopaque, namelen: i32) callconv(.c) i32;
extern "ws2_32" fn bind(s: Winsock.SOCKET, name: *const anyopaque, namelen: i32) callconv(.c) i32;
extern "ws2_32" fn send(s: Winsock.SOCKET, buf: *const anyopaque, len: i32, flags: i32) callconv(.c) i32;
extern "ws2_32" fn recv(s: Winsock.SOCKET, buf: *anyopaque, len: i32, flags: i32) callconv(.c) i32;
extern "ws2_32" fn sendto(s: Winsock.SOCKET, buf: *const anyopaque, len: i32, flags: i32, to: *const anyopaque, tolen: i32) callconv(.c) i32;
extern "ws2_32" fn closesocket(s: Winsock.SOCKET) callconv(.c) i32;
extern "ws2_32" fn listen(s: Winsock.SOCKET, backlog: i32) callconv(.c) i32;
extern "ws2_32" fn accept(s: Winsock.SOCKET, addr: ?*anyopaque, addrlen: ?*i32) callconv(.c) Winsock.SOCKET;
extern "ws2_32" fn recvfrom(s: Winsock.SOCKET, buf: *anyopaque, len: i32, flags: i32, from: ?*anyopaque, fromlen: *i32) callconv(.c) i32;
extern "ws2_32" fn getsockname(s: Winsock.SOCKET, name: *anyopaque, namelen: *i32) callconv(.c) i32;

// Aliases for the extern functions
const wsa_startup = WSAStartup;
const wsa_cleanup = WSACleanup;
const wsa_getlasterror = WSAGetLastError;
const wsa_socket = socket;
const wsa_setsockopt = setsockopt;
const wsa_connect = connect;
const wsa_bind = bind;
const wsa_send = send;
const wsa_recv = recv;
const wsa_sendto = sendto;
const wsa_closesocket = closesocket;
const wsa_listen = listen;
const wsa_accept = accept;
const wsa_recvfrom = recvfrom;
const wsa_getsockname = getsockname;
