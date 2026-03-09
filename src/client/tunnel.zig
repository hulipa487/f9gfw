const std = @import("std");

const shared = @import("shared");
const winsock_mod = @import("winsock.zig");

const Cipher = shared.crypto.Cipher;
const protocol = shared.protocol;
const TunnelHeader = protocol.TunnelHeader;
const Winsock = winsock_mod.Winsock;
const TcpTunnel = winsock_mod.TcpTunnel;

/// Client tunnel state
pub const ClientTunnel = struct {
    allocator: std.mem.Allocator,
    cipher: Cipher,
    udp_socket: Winsock.SOCKET,
    proxy_ip: [4]u8,
    proxy_port: u16,
    forward_ip: [4]u8,
    forward_port: u16,
    local_port: u16,
    ttl: u8,
    session_counter: std.atomic.Value(u32),

    const BUFFER_SIZE: usize = 65535;

    /// Initialize the client tunnel
    pub fn init(
        allocator: std.mem.Allocator,
        key: [32]u8,
        proxy_ip: [4]u8,
        proxy_port: u16,
        forward_ip: [4]u8,
        forward_port: u16,
        local_port: u16,
        ttl: u8,
    ) !ClientTunnel {
        // Initialize Winsock
        try Winsock.init();
        errdefer Winsock.deinit();

        // Create UDP socket for tunnel traffic
        const udp_socket = try Winsock.socketUdp();
        errdefer Winsock.close(udp_socket);

        // Bind UDP socket
        try Winsock.bind(udp_socket, .{ 0, 0, 0, 0 }, 0);

        return .{
            .allocator = allocator,
            .cipher = Cipher.init(key),
            .udp_socket = udp_socket,
            .proxy_ip = proxy_ip,
            .proxy_port = proxy_port,
            .forward_ip = forward_ip,
            .forward_port = forward_port,
            .local_port = local_port,
            .ttl = ttl,
            .session_counter = std.atomic.Value(u32).init(1),
        };
    }

    pub fn deinit(self: *ClientTunnel) void {
        Winsock.close(self.udp_socket);
        Winsock.deinit();
    }

    /// Handle a local TCP connection
    pub fn handleConnection(self: *ClientTunnel, client_sock: Winsock.SOCKET) !void {
        // Allocate session ID
        const session_id = self.session_counter.fetchAdd(1, .monotonic);

        // Send connect message to proxy
        try self.sendConnect(session_id);

        // Create pipes for data transfer
        var recv_buf: [BUFFER_SIZE]u8 = undefined;
        var send_buf: [BUFFER_SIZE]u8 = undefined;

        // Simple read-forward loop
        while (true) {
            // Read from client
            const bytes_read = Winsock.recv(client_sock, &recv_buf) catch |err| {
                if (err == error.ConnectionClosed) {
                    std.log.debug("Client closed connection", .{});
                    break;
                }
                return err;
            };

            if (bytes_read == 0) break;

            // Forward to proxy via UDP
            try self.sendData(session_id, recv_buf[0..bytes_read]);

            // Receive response from proxy (blocking)
            const resp_len = Winsock.recv(self.udp_socket, &send_buf) catch |err| {
                std.log.err("Failed to receive from proxy: {}", .{err});
                continue;
            };

            if (resp_len > TunnelHeader.SIZE) {
                // Parse response
                const header = TunnelHeader.deserialize(send_buf[0..TunnelHeader.SIZE]);
                if (header.isValid() and header.packet_type == .data) {
                    // Decrypt payload
                    const encrypted = send_buf[TunnelHeader.SIZE .. TunnelHeader.SIZE + header.payload_length];
                    const decrypted = self.cipher.decrypt(self.allocator, encrypted) catch {
                        continue;
                    };
                    defer self.allocator.free(decrypted);

                    // Send to client
                    _ = Winsock.send(client_sock, decrypted) catch |err| {
                        std.log.err("Failed to send to client: {}", .{err});
                        break;
                    };
                }
            }
        }

        // Send disconnect message
        try self.sendDisconnect(session_id);
    }

    /// Send connect message to proxy
    fn sendConnect(self: *ClientTunnel, session_id: u32) !void {
        // Connection info: [src_ip(4)][src_port(2)][dst_ip(4)][dst_port(2)]
        var conn_info: [12]u8 = undefined;
        // Source (we use placeholder - proxy will rewrite)
        @memcpy(conn_info[0..4], &[_]u8{ 0, 0, 0, 0 });
        std.mem.writeInt(u16, conn_info[4..6], self.local_port, .big);
        // Destination
        @memcpy(conn_info[6..10], &self.forward_ip);
        std.mem.writeInt(u16, conn_info[10..12], self.forward_port, .big);

        // Encrypt connection info
        const encrypted = try self.cipher.encrypt(self.allocator, &conn_info);
        defer self.allocator.free(encrypted);

        // Build tunnel header
        var header = TunnelHeader.init(session_id, .connect, @intCast(encrypted.len));
        header.checksum = protocol.calculateChecksum(&header, &conn_info);

        // Build packet
        const packet_len = TunnelHeader.SIZE + encrypted.len;
        const packet_buf = try self.allocator.alloc(u8, packet_len);
        defer self.allocator.free(packet_buf);

        const serialized = header.serialize();
        @memcpy(packet_buf[0..TunnelHeader.SIZE], &serialized);
        @memcpy(packet_buf[TunnelHeader.SIZE..], encrypted);

        // Send via UDP
        _ = try Winsock.sendTo(self.udp_socket, packet_buf, self.proxy_ip, self.proxy_port);
    }

    /// Send data to proxy
    fn sendData(self: *ClientTunnel, session_id: u32, data: []const u8) !void {
        // Encrypt data
        const encrypted = try self.cipher.encrypt(self.allocator, data);
        defer self.allocator.free(encrypted);

        // Build tunnel header
        var header = TunnelHeader.init(session_id, .data, @intCast(encrypted.len));
        header.checksum = protocol.calculateChecksum(&header, data);

        // Build packet
        const packet_len = TunnelHeader.SIZE + encrypted.len;
        const packet_buf = try self.allocator.alloc(u8, packet_len);
        defer self.allocator.free(packet_buf);

        const serialized = header.serialize();
        @memcpy(packet_buf[0..TunnelHeader.SIZE], &serialized);
        @memcpy(packet_buf[TunnelHeader.SIZE..], encrypted);

        // Send via UDP
        _ = try Winsock.sendTo(self.udp_socket, packet_buf, self.proxy_ip, self.proxy_port);
    }

    /// Send disconnect message
    fn sendDisconnect(self: *ClientTunnel, session_id: u32) !void {
        // Build tunnel header
        var header = TunnelHeader.init(session_id, .disconnect, 0);
        header.checksum = protocol.calculateChecksum(&header, &[_]u8{});

        // Build packet
        const packet_buf = try self.allocator.alloc(u8, TunnelHeader.SIZE);
        defer self.allocator.free(packet_buf);

        const serialized = header.serialize();
        @memcpy(packet_buf[0..TunnelHeader.SIZE], &serialized);

        // Send via UDP
        _ = try Winsock.sendTo(self.udp_socket, packet_buf, self.proxy_ip, self.proxy_port);
    }

    /// Create TTL-limited SYN for NAT traversal
    pub fn createNATEntry(self: *ClientTunnel) !void {
        // Create a TCP connection with limited TTL
        // This sends SYN packets that expire at ISP router,
        // creating NAT entry without reaching destination
        var tunnel = try TcpTunnel.initTTLLimited(
            self.forward_ip,
            self.forward_port,
            self.ttl,
        );
        defer tunnel.deinit();

        std.log.debug("Created NAT entry via TTL-limited SYN, local port: {}", .{tunnel.local_port});
    }
};

/// Local TCP listener that accepts connections and tunnels them
pub const LocalListener = struct {
    tunnel: *ClientTunnel,
    listen_sock: Winsock.SOCKET,
    listen_port: u16,

    pub fn init(tunnel: *ClientTunnel, port: u16) !LocalListener {
        const sock = try Winsock.socketTcp();
        errdefer Winsock.close(sock);

        // Set reuse address
        var opt: u32 = 1;
        _ = winsock_mod.setsockopt_internal(
            sock,
            Winsock.SOL_SOCKET,
            Winsock.SO_REUSEADDR,
            @ptrCast(&opt),
            @sizeOf(u32),
        );

        try Winsock.bind(sock, .{ 127, 0, 0, 1 }, port);

        // Listen
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

            const client_sock = Winsock.accept(
                self.listen_sock,
                &client_addr,
                &client_addr_len,
            ) catch {
                std.log.err("Accept failed", .{});
                continue;
            };

            std.log.info("Accepted connection", .{});

            // Handle connection in same thread (could spawn thread for concurrency)
            self.tunnel.handleConnection(client_sock) catch |err| {
                std.log.err("Connection error: {}", .{err});
            };

            Winsock.close(client_sock);
        }
    }
};
