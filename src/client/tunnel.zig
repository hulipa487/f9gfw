const std = @import("std");

const shared = @import("shared");
const winsock_mod = @import("winsock.zig");
const wfp_mod = @import("wfp.zig");

const Cipher = shared.crypto.Cipher;
const protocol = shared.protocol;
const icmp = shared.icmp;
const packet_mod = shared.packet;
const TunnelHeader = protocol.TunnelHeader;
const Winsock = winsock_mod.Winsock;
const PacketCapturer = wfp_mod.PacketCapturer;
const WinDivert = wfp_mod.WinDivert;

/// NAT info discovered via ICMP Time Exceeded
pub const NATInfo = struct {
    public_ip: [4]u8,
    public_port: u16,
};

/// Capture context for WinDivert callback
pub const CaptureContext = struct {
    tunnel: *ClientTunnel,
    session_id: u32,
    stream_b_local_port: u16,
    nat_info: NATInfo,
    forward_ip: [4]u8,
    forward_port: u16,
};

/// Client tunnel state
pub const ClientTunnel = struct {
    allocator: std.mem.Allocator,
    cipher: Cipher,
    udp_socket: Winsock.SOCKET,
    icmp_socket: Winsock.SOCKET,
    proxy_ip: [4]u8,
    proxy_port: u16,
    forward_ip: [4]u8,
    forward_port: u16,
    ttl: u8,
    session_counter: std.atomic.Value(u32),

    const BUFFER_SIZE: usize = 65535;
    const ICMP_TIMEOUT_MS: i32 = 5000;

    /// Initialize the client tunnel
    pub fn init(
        allocator: std.mem.Allocator,
        key: [32]u8,
        proxy_ip: [4]u8,
        proxy_port: u16,
        forward_ip: [4]u8,
        forward_port: u16,
        ttl: u8,
    ) !ClientTunnel {
        try Winsock.init();
        errdefer Winsock.deinit();

        const udp_socket = try Winsock.socketUdp();
        errdefer Winsock.close(udp_socket);
        try Winsock.bind(udp_socket, .{ 0, 0, 0, 0 }, 0);

        // ICMP socket for capturing Time Exceeded
        const icmp_socket: Winsock.SOCKET = Winsock.socketIcmp() catch blk: {
            std.log.warn("Could not create ICMP socket (requires admin)", .{});
            break :blk Winsock.INVALID_SOCKET;
        };
        errdefer if (icmp_socket != Winsock.INVALID_SOCKET) Winsock.close(icmp_socket);

        return .{
            .allocator = allocator,
            .cipher = Cipher.init(key),
            .udp_socket = udp_socket,
            .icmp_socket = icmp_socket,
            .proxy_ip = proxy_ip,
            .proxy_port = proxy_port,
            .forward_ip = forward_ip,
            .forward_port = forward_port,
            .ttl = ttl,
            .session_counter = std.atomic.Value(u32).init(1),
        };
    }

    pub fn deinit(self: *ClientTunnel) void {
        Winsock.close(self.udp_socket);
        if (self.icmp_socket != Winsock.INVALID_SOCKET) {
            Winsock.close(self.icmp_socket);
        }
        Winsock.deinit();
    }

    /// Handle a local TCP connection (Stream A)
    /// This creates Stream B (TTL-limited TCP) and tunnels via Stream C (UDP)
    pub fn handleConnection(self: *ClientTunnel, client_sock: Winsock.SOCKET) !void {
        const session_id = self.session_counter.fetchAdd(1, .monotonic);

        // Create Stream B: TCP socket with TTL for NAT traversal
        const stream_b_sock = try Winsock.socketTcp();
        defer Winsock.close(stream_b_sock);

        try Winsock.setTTL(stream_b_sock, self.ttl);
        try Winsock.bind(stream_b_sock, .{ 0, 0, 0, 0 }, 0);

        // Get local port of Stream B (needed to match ICMP response)
        var local_addr: Winsock.sockaddr_in = undefined;
        try Winsock.getSockName(stream_b_sock, &local_addr);
        const stream_b_local_port = std.mem.bigToNative(u16, local_addr.sin_port);

        std.log.info("Session {}: Stream B local port {}", .{ session_id, stream_b_local_port });

        // Start non-blocking connect (sends SYN with TTL)
        // This creates NAT entry but packet expires before reaching destination
        Winsock.connect(stream_b_sock, self.forward_ip, self.forward_port) catch {};

        // Wait for ICMP Time Exceeded to get NAT-translated src IP/port
        const nat_info = self.waitForNATInfo(stream_b_local_port) catch |err| blk: {
            std.log.warn("NAT discovery failed: {} - connection may not work", .{err});
            break :blk null;
        };

        var capture_ctx: ?CaptureContext = null;
        var capturer: ?PacketCapturer = null;

        if (nat_info) |nat| {
            std.log.info("Session {}: NAT public endpoint {}.{}.{}.{}:{}", .{
                session_id,
                nat.public_ip[0], nat.public_ip[1], nat.public_ip[2], nat.public_ip[3],
                nat.public_port,
            });

            // Send connect message to proxy with NAT info
            try self.sendConnect(session_id, nat);

            // Initialize capture context for WinDivert callback
            capture_ctx = .{
                .tunnel = self,
                .session_id = session_id,
                .stream_b_local_port = stream_b_local_port,
                .nat_info = nat,
                .forward_ip = self.forward_ip,
                .forward_port = self.forward_port,
            };

            // Start WinDivert packet capture
            capturer = try PacketCapturer.init(self.allocator, .{
                .dst_ip = self.forward_ip,
                .dst_port = self.forward_port,
                .protocol = 6, // TCP
            });

            try capturer.?.start(captureCallback, &capture_ctx.?);

            // Small delay to ensure filter is active before we start sending
            std.os.windows.kernel32.Sleep(100);
        }

        // Pipe data bidirectionally:
        // Stream A (client_sock) -> Stream B (triggers WFP capture)
        // Stream B (server responses) -> Stream A
        // Stream C (UDP tunnel) -> Stream A

        try self.pipeConnection(
            session_id,
            client_sock,      // Stream A
            stream_b_sock,    // Stream B
            nat_info,
            &capturer,
        );
    }

    /// Wait for ICMP Time Exceeded and extract NAT info
    fn waitForNATInfo(self: *ClientTunnel, local_port: u16) !NATInfo {
        if (self.icmp_socket == Winsock.INVALID_SOCKET) {
            return error.ICMPSocketNotAvailable;
        }

        var icmp_buf: [1024]u8 = undefined;
        var from_ip: [4]u8 = undefined;
        var from_port: u16 = undefined;

        const start_time = std.time.milliTimestamp();
        while (std.time.milliTimestamp() - start_time < ICMP_TIMEOUT_MS) {
            const recv_len = Winsock.recvFrom(self.icmp_socket, &icmp_buf, &from_ip, &from_port) catch {
                std.os.windows.kernel32.Sleep(10);
                continue;
            };

            if (icmp.parseTimeExceeded(icmp_buf[0..recv_len], from_ip)) |info| {
                // Match by destination and local port
                if (std.mem.eql(u8, &info.orig_dst_ip, &self.forward_ip) and
                    info.orig_dst_port == self.forward_port and
                    info.orig_src_port == local_port)
                {
                    return .{
                        .public_ip = info.orig_src_ip,
                        .public_port = info.orig_src_port,
                    };
                }
            }
        }

        return error.ICMPTimeout;
    }

    /// Pipe data between Stream A, Stream B, and Stream C
    fn pipeConnection(
        self: *ClientTunnel,
        session_id: u32,
        stream_a: Winsock.SOCKET, // Local app connection
        stream_b: Winsock.SOCKET, // Real TCP to server
        _nat_info: ?NATInfo,
        capturer: *?PacketCapturer,
    ) !void {
        _ = _nat_info;
        var buf_a: [BUFFER_SIZE]u8 = undefined; // From local app
        var buf_c: [BUFFER_SIZE]u8 = undefined; // From UDP tunnel

        // Use select() or poll() equivalent for bidirectional I/O
        // For simplicity, we'll use non-blocking reads in a loop

        while (true) {
            var got_data = false;

            // Read from Stream A (local app) -> forward to Stream B
            if (Winsock.recv(stream_a, &buf_a)) |len| {
                if (len == 0) break; // Connection closed
                got_data = true;

                // Write to Stream B (kernel will generate TCP packets)
                // WinDivert captures these packets for tunneling
                _ = Winsock.send(stream_b, buf_a[0..len]) catch {
                    std.log.err("Session {}: Stream B send failed", .{session_id});
                    break;
                };
            } else |_| {}

            // Read from Stream B (server responses) -> forward to Stream A
            if (Winsock.recv(stream_b, &buf_a)) |len| {
                if (len == 0) break;
                got_data = true;

                // Forward server response to local app
                _ = Winsock.send(stream_a, buf_a[0..len]) catch {
                    std.log.err("Session {}: Stream A send failed", .{session_id});
                    break;
                };
            } else |_| {}

            // Read from Stream C (UDP tunnel) -> forward to Stream A
            // This is for responses from proxy server
            if (Winsock.recv(self.udp_socket, &buf_c)) |len| {
                if (len > TunnelHeader.SIZE) {
                    got_data = true;
                    const header = TunnelHeader.deserialize(buf_c[0..TunnelHeader.SIZE]);
                    if (header.isValid() and header.packet_type == .data) {
                        const encrypted = buf_c[TunnelHeader.SIZE .. TunnelHeader.SIZE + header.payload_length];
                        if (self.cipher.decrypt(self.allocator, encrypted)) |decrypted| {
                            defer self.allocator.free(decrypted);
                            _ = Winsock.send(stream_a, decrypted) catch {};
                        } else |_| {}
                    }
                }
            } else |_| {}

            if (!got_data) {
                std.os.windows.kernel32.Sleep(1);
            }
        }

        // Stop capture
        if (capturer.*) |*cap| {
            cap.stop();
        }

        try self.sendDisconnect(session_id);
    }

    /// Send connect message to proxy
    fn sendConnect(self: *ClientTunnel, session_id: u32, nat: NATInfo) !void {
        var conn_info: [12]u8 = undefined;
        @memcpy(conn_info[0..4], &nat.public_ip);
        std.mem.writeInt(u16, conn_info[4..6], nat.public_port, .big);
        @memcpy(conn_info[6..10], &self.forward_ip);
        std.mem.writeInt(u16, conn_info[10..12], self.forward_port, .big);

        const encrypted = try self.cipher.encrypt(self.allocator, &conn_info);
        defer self.allocator.free(encrypted);

        var header = TunnelHeader.init(session_id, .connect, @intCast(encrypted.len));
        header.checksum = protocol.calculateChecksum(&header, &conn_info);

        const packet_buf = try self.allocator.alloc(u8, TunnelHeader.SIZE + encrypted.len);
        defer self.allocator.free(packet_buf);

        const serialized = header.serialize();
        @memcpy(packet_buf[0..TunnelHeader.SIZE], &serialized);
        @memcpy(packet_buf[TunnelHeader.SIZE..], encrypted);

        _ = try Winsock.sendTo(self.udp_socket, packet_buf, self.proxy_ip, self.proxy_port);
    }

    /// Send disconnect message
    fn sendDisconnect(self: *ClientTunnel, session_id: u32) !void {
        var header = TunnelHeader.init(session_id, .disconnect, 0);
        header.checksum = protocol.calculateChecksum(&header, &[_]u8{});

        const packet_buf = try self.allocator.alloc(u8, TunnelHeader.SIZE);
        defer self.allocator.free(packet_buf);

        const serialized = header.serialize();
        @memcpy(packet_buf[0..TunnelHeader.SIZE], &serialized);

        _ = try Winsock.sendTo(self.udp_socket, packet_buf, self.proxy_ip, self.proxy_port);
    }
};

/// WinDivert capture callback - called for each captured packet
fn captureCallback(packet: []const u8, _addr: *const WinDivert.ADDR, user_data: *anyopaque) void {
    _ = _addr;
    const ctx = @as(*CaptureContext, @ptrCast(@alignCast(user_data)));

    // Parse the captured packet
    const ip_header = packet_mod.IPv4Header.parse(packet[0..]) catch {
        std.log.warn("Failed to parse IP header", .{});
        return;
    };

    // Only capture TCP packets from our Stream B socket
    if (ip_header.protocol != 6) return;

    const header_len = @as(usize, ip_header.ihl) * 4;
    if (packet.len < header_len + packet_mod.TCPHeader.MIN_SIZE) return;

    const tcp_header = packet_mod.TCPHeader.parse(packet[header_len..]) catch return;

    // Verify this is from our Stream B socket (check source port)
    if (tcp_header.source_port != ctx.stream_b_local_port) return;

    // Rewrite source IP and port to NAT-discovered values
    var packet_buf = std.heap.page_allocator.alloc(u8, packet.len) catch return;
    defer std.heap.page_allocator.free(packet_buf);
    @memcpy(packet_buf, packet);

    // Rewrite to NAT public IP/port
    const new_src_addr = std.mem.nativeToBig(u32, @bitCast(ctx.nat_info.public_ip));
    std.mem.writeInt(u32, packet_buf[12..16], new_src_addr, .big);
    std.mem.writeInt(u16, packet_buf[header_len..][0..2], ctx.nat_info.public_port, .big);

    // Recalculate IP checksum
    const ip_cksum = packet_mod.checksumIPv4(packet_buf[0..header_len]);
    std.mem.writeInt(u16, packet_buf[10..12], ip_cksum, .big);

    // Recalculate TCP checksum
    std.mem.writeInt(u16, packet_buf[header_len + 16 ..][0..2], 0, .big);
    const tcp_cksum = packet_mod.checksumTCP(
        packet_buf[header_len .. header_len + 20],
        if (packet.len > header_len + 20) packet_buf[header_len + 20..] else &[_]u8{},
        ctx.nat_info.public_ip,
        ip_header.getDestIP(),
    );
    std.mem.writeInt(u16, packet_buf[header_len + 16 ..][0..2], tcp_cksum, .big);

    // Encrypt the rewritten packet
    const cipher = &ctx.tunnel.cipher;
    const encrypted = cipher.encrypt(ctx.tunnel.allocator, packet_buf) catch {
        std.log.err("Session {}: Encryption failed", .{ctx.session_id});
        return;
    };
    defer ctx.tunnel.allocator.free(encrypted);

    // Build tunnel packet
    var header = TunnelHeader.init(ctx.session_id, .data, @intCast(encrypted.len));
    header.checksum = protocol.calculateChecksum(&header, packet_buf);

    const packet_buf_total = ctx.tunnel.allocator.alloc(u8, TunnelHeader.SIZE + encrypted.len) catch return;
    defer ctx.tunnel.allocator.free(packet_buf_total);

    const serialized = header.serialize();
    @memcpy(packet_buf_total[0..TunnelHeader.SIZE], &serialized);
    @memcpy(packet_buf_total[TunnelHeader.SIZE..], encrypted);

    // Send via UDP to proxy
    _ = Winsock.sendTo(ctx.tunnel.udp_socket, packet_buf_total, ctx.tunnel.proxy_ip, ctx.tunnel.proxy_port) catch {
        std.log.err("Session {}: UDP send failed", .{ctx.session_id});
        return;
    };
}

/// Local TCP listener
pub const LocalListener = struct {
    tunnel: *ClientTunnel,
    listen_sock: Winsock.SOCKET,
    listen_port: u16,

    pub fn init(tunnel: *ClientTunnel, port: u16) !LocalListener {
        const sock = try Winsock.socketTcp();
        errdefer Winsock.close(sock);

        var opt: u32 = 1;
        _ = winsock_mod.setsockopt_internal(sock, Winsock.SOL_SOCKET, Winsock.SO_REUSEADDR, @ptrCast(&opt), @sizeOf(u32));

        try Winsock.bind(sock, .{ 127, 0, 0, 1 }, port);
        try Winsock.listen(sock, 5);

        return .{
            .tunnel = tunnel,
            .listen_sock = sock,
            .listen_port = port,
        };
    }

    pub fn deinit(self: *LocalListener) void {
        Winsock.close(self.listen_sock);
    }

    pub fn run(self: *LocalListener) !void {
        std.log.info("Listening on 127.0.0.1:{}", .{self.listen_port});

        while (true) {
            var client_addr: Winsock.sockaddr_in = undefined;
            var client_addr_len: i32 = @sizeOf(Winsock.sockaddr_in);

            const client_sock = Winsock.accept(self.listen_sock, &client_addr, &client_addr_len) catch {
                std.log.err("Accept failed", .{});
                continue;
            };

            std.log.info("Accepted connection", .{});

            self.tunnel.handleConnection(client_sock) catch |err| {
                std.log.err("Connection error: {}", .{err});
            };

            Winsock.close(client_sock);
        }
    }
};
