const std = @import("std");
const linux = std.os.linux;
const shared = @import("shared");

const packet = shared.packet;

/// Raw socket for injecting TCP packets into the kernel network stack
pub const PacketInjector = struct {
    fd: i32,

    pub fn init() !PacketInjector {
        // Create raw socket
        const fd = try std.posix.socket(
            std.posix.AF.INET,
            std.posix.SOCK.RAW,
            std.posix.IPPROTO.RAW,
        );
        errdefer std.posix.close(fd);

        // Set IP_HDRINCL to include our own IP header
        const opt: i32 = 1;
        try std.posix.setsockopt(
            fd,
            std.posix.IPPROTO.IP,
            std.posix.IP.HDRINCL,
            std.mem.asBytes(&opt),
        );

        return .{ .fd = fd };
    }

    pub fn deinit(self: *PacketInjector) void {
        std.posix.close(self.fd);
    }

    /// Inject a TCP/IP packet
    pub fn inject(self: *PacketInjector, packet_data: []const u8, dest_ip: [4]u8, dest_port: u16) !usize {
        _ = dest_port; // Already in the packet

        // Parse the packet to validate
        const ip_header = try packet.IPv4Header.parse(packet_data);

        // Verify it's a TCP packet
        if (ip_header.protocol != packet.IPv4Header.PROTOCOL_TCP) {
            return error.NotTCPPacket;
        }

        // Create destination address
        var dest_addr: std.posix.sockaddr.in = .{
            .addr = @bitCast(dest_ip),
            .port = 0, // Ignored for raw sockets
            .family = std.posix.AF.INET,
            .zero = [_]u8{0} ** 8,
        };

        // Send the packet
        const addr = @as(*const std.posix.sockaddr, @ptrCast(&dest_addr));
        const sent = std.posix.sendto(
            self.fd,
            packet_data,
            0,
            addr,
            @sizeOf(std.posix.sockaddr.in),
        ) catch |err| {
            std.log.err("Failed to inject packet: {}", .{err});
            return err;
        };

        return sent;
    }

    /// Rewrite source IP and inject packet
    pub fn injectWithRewrite(
        self: *PacketInjector,
        packet_data: []u8,
        new_src_ip: [4]u8,
        dest_ip: [4]u8,
    ) !usize {
        // Rewrite source IP and recalculate checksums
        try packet.rewriteSourceIP(packet_data, new_src_ip);

        // Extract destination port from packet
        const ip_header = try packet.IPv4Header.parse(packet_data);
        const header_len = @as(usize, ip_header.ihl) * 4;
        const tcp_header = try packet.TCPHeader.parse(packet_data[header_len..]);

        return self.inject(packet_data, dest_ip, tcp_header.dest_port);
    }
};

/// Alternative: Use TUN/TAP device for more control
pub const TunDevice = struct {
    fd: i32,
    dev_name: [16]u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, name: ?[]const u8) !TunDevice {
        // Open /dev/net/tun
        const fd = try std.posix.open(
            "/dev/net/tun",
            std.posix.O{ .ACCMODE = .RDWR, .CLOEXEC = true },
            0,
        );
        errdefer std.posix.close(fd);

        // Setup TUN interface
        var iff: linux.ifreq = std.mem.zeroes(linux.ifreq);
        iff.ifrn.name[0..15].* = if (name) |n| blk: {
            var buf = [_]u8{0} ** 16;
            @memcpy(buf[0..@min(n.len, 15)], n);
            break :blk buf;
        } else [_]u8{0} ** 16;

        // TUN device with no packet info
        iff.ifru.flags = linux.IFF.TUN | linux.IFF.NO_PI;

        const err = linux.ioctl(fd, linux.TUN.SETIFF, @intFromPtr(&iff));
        if (linux.E.init(err)) |_| {
            return error.TunSetupFailed;
        }

        var dev_name: [16]u8 = undefined;
        @memcpy(&dev_name, &iff.ifrn.name);

        return .{
            .fd = fd,
            .dev_name = dev_name,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *TunDevice) void {
        std.posix.close(self.fd);
    }

    pub fn read(self: *TunDevice, buf: []u8) !usize {
        return std.posix.read(self.fd, buf);
    }

    pub fn write(self: *TunDevice, data: []const u8) !usize {
        return std.posix.write(self.fd, data);
    }

    pub fn getDeviceName(self: *const TunDevice) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.dev_name, 0) orelse 16;
        return self.dev_name[0..len];
    }
};

test "PacketInjector initialization placeholder" {
    // This test requires root privileges
    if (std.os.linux.getuid() != 0) {
        return error.SkipZigTest;
    }
}
