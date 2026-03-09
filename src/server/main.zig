const std = @import("std");

const shared = @import("shared");
const iouring = @import("iouring.zig");
const injector = @import("injector.zig");

const Cipher = shared.crypto.Cipher;
const packet = shared.packet;
const protocol = shared.protocol;
const tunnel = shared.tunnel;
const TunnelHeader = protocol.TunnelHeader;
const SessionManager = tunnel.SessionManager;
const UdpRing = iouring.UdpRing;
const PacketInjector = injector.PacketInjector;

const DEFAULT_PORT: u16 = 51820;

pub const std_options: std.Options = .{
    .log_level = .info,
};

const Server = struct {
    allocator: std.mem.Allocator,
    cipher: Cipher,
    udp_ring: UdpRing,
    injector: PacketInjector,
    sessions: SessionManager(1024),
    listen_addr: std.net.Address,

    pub fn init(
        allocator: std.mem.Allocator,
        listen_addr: std.net.Address,
        key: [32]u8,
    ) !Server {
        var udp_ring = try UdpRing.init(allocator, listen_addr);
        errdefer udp_ring.deinit();

        var pkt_injector = try PacketInjector.init();
        errdefer pkt_injector.deinit();

        return .{
            .allocator = allocator,
            .cipher = Cipher.init(key),
            .udp_ring = udp_ring,
            .injector = pkt_injector,
            .sessions = SessionManager(1024).init(allocator),
            .listen_addr = listen_addr,
        };
    }

    pub fn deinit(self: *Server) void {
        self.udp_ring.deinit();
        self.injector.deinit();
        self.sessions.deinit();
    }

    pub fn run(self: *Server) !void {
        std.log.info("Server listening on {f}", .{self.listen_addr});

        // Prepare initial receive
        try self.udp_ring.prepareRecv(@intFromEnum(iouring.OpTag.recv));

        while (true) {
            const cqe = try self.udp_ring.waitCompletion();

            switch (@as(iouring.OpTag, @enumFromInt(cqe.user_data))) {
                .recv => {
                    if (cqe.res < 0) {
                        std.log.err("Recv error: {}", .{-cqe.res});
                        try self.udp_ring.prepareRecv(@intFromEnum(iouring.OpTag.recv));
                        continue;
                    }

                    const bytes_received: usize = @intCast(cqe.res);
                    const buffer = self.udp_ring.getBuffer();

                    // Process the packet
                    self.handlePacket(buffer[0..bytes_received]) catch |err| {
                        std.log.err("Error handling packet: {}", .{err});
                    };

                    // Prepare next receive
                    try self.udp_ring.prepareRecv(@intFromEnum(iouring.OpTag.recv));
                },
                .send => {
                    if (cqe.res < 0) {
                        std.log.err("Send error: {}", .{-cqe.res});
                    }
                },
                _ => {
                    // Unknown operation, ignore
                    std.log.debug("Unknown op tag: {}", .{cqe.user_data});
                },
            }

            // Periodic cleanup
            // TODO: Add timer-based cleanup
        }
    }

    fn handlePacket(self: *Server, data: []u8) !void {
        if (data.len < TunnelHeader.SIZE) {
            return error.PacketTooSmall;
        }

        // Parse tunnel header
        const header = TunnelHeader.deserialize(data[0..TunnelHeader.SIZE]);
        if (!header.isValid()) {
            return error.InvalidPacket;
        }

        // Get encrypted payload
        const encrypted_payload = data[TunnelHeader.SIZE .. TunnelHeader.SIZE + header.payload_length];
        if (encrypted_payload.len != header.payload_length) {
            return error.LengthMismatch;
        }

        // Decrypt payload
        const decrypted = self.cipher.decrypt(self.allocator, encrypted_payload) catch {
            return error.DecryptionFailed;
        };
        defer self.allocator.free(decrypted);

        // Verify checksum
        const calculated_checksum = protocol.calculateChecksum(&header, decrypted);
        if (calculated_checksum != header.checksum) {
            return error.ChecksumMismatch;
        }

        // Handle based on packet type
        switch (header.packet_type) {
            .data => try self.handleDataPacket(header.session_id, decrypted),
            .connect => try self.handleConnectPacket(decrypted),
            .disconnect => try self.handleDisconnectPacket(header.session_id),
            .keepalive => {}, // Just verify and acknowledge
            .ack => {}, // Acknowledgment, nothing to do
        }
    }

    fn handleDataPacket(self: *Server, session_id: u32, tcp_packet: []u8) !void {
        // Get or create session
        const session = self.sessions.getSession(session_id) orelse {
            return error.UnknownSession;
        };

        session.touch();
        session.bytes_received += tcp_packet.len;

        // Parse IP header to get destination
        const ip_header = try packet.IPv4Header.parse(tcp_packet);
        const dest_ip = ip_header.getDestIP();
        const header_len = @as(usize, ip_header.ihl) * 4;

        // Parse TCP header to get destination port
        const tcp_header = try packet.TCPHeader.parse(tcp_packet[header_len..]);
        const dest_port = tcp_header.dest_port;

        // Rewrite source IP to client's original IP
        // This makes the packet appear to come from the original client
        const packet_copy = try self.allocator.alloc(u8, tcp_packet.len);
        defer self.allocator.free(packet_copy);
        @memcpy(packet_copy, tcp_packet);

        // Use the session's client address as the new source IP
        const new_src_ip = @as([4]u8, @bitCast(session.client_addr.in.sa.addr));
        try packet.rewriteSourceIP(packet_copy, new_src_ip);

        // Inject packet into kernel
        _ = try self.injector.inject(packet_copy, dest_ip, dest_port);

        std.log.debug("Injected packet: {} bytes, session {}", .{ tcp_packet.len, session_id });
    }

    fn handleConnectPacket(self: *Server, conn_info: []u8) !void {
        // Connection info format: [src_ip(4)][src_port(2)][dst_ip(4)][dst_port(2)]
        if (conn_info.len < 12) {
            return error.InvalidConnectionInfo;
        }

        const src_ip: [4]u8 = conn_info[0..4].*;
        const src_port = std.mem.readInt(u16, conn_info[4..6], .big);
        const dst_ip: [4]u8 = conn_info[6..10].*;
        const dst_port = std.mem.readInt(u16, conn_info[10..12], .big);

        const conn_id = tunnel.ConnectionId.init(src_ip, src_port, dst_ip, dst_port);
        const client_addr = std.net.Address.initIp4(src_ip, src_port);

        const session = try self.sessions.createSession(conn_id, client_addr);
        session.state = .established;

        std.log.info("New connection: {f} -> {f} (session {})", .{
            conn_id.src,
            conn_id.dst,
            session.id,
        });
    }

    fn handleDisconnectPacket(self: *Server, session_id: u32) !void {
        if (self.sessions.getSession(session_id)) |session| {
            std.log.info("Connection closed: session {} (sent {} bytes, received {} bytes)", .{
                session.id,
                session.bytes_sent,
                session.bytes_received,
            });
        }
        self.sessions.removeSession(session_id);
    }
};

fn parseArgs(allocator: std.mem.Allocator) !struct {
    listen_ip: []const u8,
    port: u16,
    key: []const u8,
} {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var listen_ip: ?[]const u8 = null;
    var port: u16 = DEFAULT_PORT;
    var key: ?[]const u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-l")) {
            listen_ip = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse return error.MissingArgument;
            port = try std.fmt.parseInt(u16, port_str, 10);
        } else if (std.mem.eql(u8, arg, "-k")) {
            key = args.next() orelse return error.MissingArgument;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        }
    }

    return .{
        .listen_ip = listen_ip orelse "0.0.0.0",
        .port = port,
        .key = key orelse return error.MissingKey,
    };
}

fn printUsage() void {
    std.log.info(
        \\f9gfw - TCP/UDP Proxy Server
        \\
        \\Usage: f9gfw -k <key> [options]
        \\
        \\Options:
        \\  -l <ip>       Listen IP address (default: 0.0.0.0)
        \\  -p <port>     Listen UDP port (default: {d})
        \\  -k <key>      Pre-shared encryption key (required)
        \\  -h, --help    Show this help message
        \\
    , .{DEFAULT_PORT});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = parseArgs(allocator) catch |err| {
        std.log.err("Failed to parse arguments: {}", .{err});
        printUsage();
        std.process.exit(1);
    };

    // Derive encryption key
    const key = Cipher.deriveKey(args.key);

    // Parse listen address
    const listen_addr = std.net.Address.parseIp(args.listen_ip, args.port) catch |err| {
        std.log.err("Invalid listen address: {}", .{err});
        std.process.exit(1);
    };

    // Initialize and run server
    var server = Server.init(allocator, listen_addr, key) catch |err| {
        std.log.err("Failed to initialize server: {}", .{err});
        std.process.exit(1);
    };
    defer server.deinit();

    server.run() catch |err| {
        std.log.err("Server error: {}", .{err});
        std.process.exit(1);
    };
}
