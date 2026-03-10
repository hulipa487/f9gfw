const std = @import("std");

const shared = @import("shared");
const winsock_mod = @import("winsock.zig");
const tunnel_mod = @import("tunnel.zig");

const Cipher = shared.crypto.Cipher;
const Winsock = winsock_mod.Winsock;
const ClientTunnel = tunnel_mod.ClientTunnel;
const LocalListener = tunnel_mod.LocalListener;

const DEFAULT_LOCAL_PORT: u16 = 1080;
const DEFAULT_PROXY_PORT: u16 = 51820;
const DEFAULT_TTL: u8 = 2;

pub const std_options: std.Options = .{
    .log_level = .info,
};

const Args = struct {
    local_port: u16,
    forward_addr: []const u8,
    forward_port: u16,
    proxy_addr: []const u8,
    proxy_port: u16,
    key: []const u8,
    ttl: u8,
};

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();

    var local_port: u16 = DEFAULT_LOCAL_PORT;
    var forward_addr: ?[]const u8 = null;
    var forward_port: u16 = 80;
    var proxy_addr: ?[]const u8 = null;
    var proxy_port: u16 = DEFAULT_PROXY_PORT;
    var key: ?[]const u8 = null;
    var ttl: u8 = DEFAULT_TTL;

    // Temporary storage for strings we need to modify
    var forward_addr_buf: ?[]u8 = null;
    var proxy_addr_buf: ?[]u8 = null;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-l")) {
            const port_str = args.next() orelse return error.MissingArgument;
            local_port = try std.fmt.parseInt(u16, port_str, 10);
        } else if (std.mem.eql(u8, arg, "-f")) {
            const raw_addr = args.next() orelse return error.MissingArgument;
            // Parse "ip:port" format
            if (std.mem.indexOfScalar(u8, raw_addr, ':')) |colon| {
                forward_port = try std.fmt.parseInt(u16, raw_addr[colon + 1 ..], 10);
                forward_addr_buf = try allocator.dupe(u8, raw_addr[0..colon]);
                forward_addr = forward_addr_buf.?;
            } else {
                forward_addr_buf = try allocator.dupe(u8, raw_addr);
                forward_addr = forward_addr_buf.?;
            }
        } else if (std.mem.eql(u8, arg, "-c")) {
            const raw_addr = args.next() orelse return error.MissingArgument;
            // Parse "ip:port" format
            if (std.mem.indexOfScalar(u8, raw_addr, ':')) |colon| {
                proxy_port = try std.fmt.parseInt(u16, raw_addr[colon + 1 ..], 10);
                proxy_addr_buf = try allocator.dupe(u8, raw_addr[0..colon]);
                proxy_addr = proxy_addr_buf.?;
            } else {
                proxy_addr_buf = try allocator.dupe(u8, raw_addr);
                proxy_addr = proxy_addr_buf.?;
            }
        } else if (std.mem.eql(u8, arg, "-p")) {
            const port_str = args.next() orelse return error.MissingArgument;
            proxy_port = try std.fmt.parseInt(u16, port_str, 10);
        } else if (std.mem.eql(u8, arg, "-k")) {
            const raw_key = args.next() orelse return error.MissingArgument;
            key = try allocator.dupe(u8, raw_key);
        } else if (std.mem.eql(u8, arg, "--ttl") or std.mem.eql(u8, arg, "-ttl")) {
            const ttl_str = args.next() orelse return error.MissingArgument;
            ttl = try std.fmt.parseInt(u8, ttl_str, 10);
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        }
    }

    return .{
        .local_port = local_port,
        .forward_addr = forward_addr orelse return error.MissingForwardAddr,
        .forward_port = forward_port,
        .proxy_addr = proxy_addr orelse return error.MissingProxyAddr,
        .proxy_port = proxy_port,
        .key = key orelse return error.MissingKey,
        .ttl = ttl,
    };
}

fn printUsage() void {
    std.log.info(
        \\f9gfwc - TCP/UDP Proxy Client
        \\
        \\Usage: f9gfwc -f <forward_addr> -c <proxy_addr> -k <key> [options]
        \\
        \\Options:
        \\  -l <port>           Local TCP listen port (default: {d})
        \\  -f <ip[:port]>      Forward address (destination server)
        \\  -c <ip[:port]>      Proxy server address
        \\  -p <port>           Proxy UDP port (default: {d})
        \\  -k <key>            Pre-shared encryption key (required)
        \\  -ttl <n>            TTL for NAT traversal SYNs (default: {d})
        \\  -h, --help          Show this help message
        \\
        \\Example:
        \\  f9gfwc -l 1080 -f 93.184.216.34:80 -c 192.168.1.100 -p 51820 -k mysecretkey -ttl 2
        \\
    , .{ DEFAULT_LOCAL_PORT, DEFAULT_PROXY_PORT, DEFAULT_TTL });
}

fn parseIPv4(allocator: std.mem.Allocator, addr_str: []const u8) ![4]u8 {
    // Make a copy to work with
    const buf = try allocator.dupe(u8, addr_str);
    defer allocator.free(buf);

    var ip: [4]u8 = undefined;
    var i: usize = 0;
    var start: usize = 0;

    for (buf, 0..) |c, j| {
        if (c == '.') {
            if (i >= 4) return error.InvalidIPAddress;
            ip[i] = try std.fmt.parseInt(u8, buf[start..j], 10);
            i += 1;
            start = j + 1;
        }
    }

    // Parse the last octet
    if (i >= 4) return error.InvalidIPAddress;
    ip[i] = try std.fmt.parseInt(u8, buf[start..], 10);
    i += 1;

    if (i != 4) return error.InvalidIPAddress;
    return ip;
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

    // Parse IP addresses
    const forward_ip = parseIPv4(allocator, args.forward_addr) catch |err| {
        std.log.err("Invalid forward address: '{s}' ({})", .{ args.forward_addr, err });
        printUsage();
        std.process.exit(1);
    };
    const proxy_ip = parseIPv4(allocator, args.proxy_addr) catch |err| {
        std.log.err("Invalid proxy address: '{s}' ({})", .{ args.proxy_addr, err });
        printUsage();
        std.process.exit(1);
    };

    // Derive encryption key
    const key = Cipher.deriveKey(args.key);

    std.log.info("Starting f9gfw client", .{});
    std.log.info("Local: 127.0.0.1:{}", .{args.local_port});
    std.log.info("Forward: {}.{}.{}.{}:{}", .{ forward_ip[0], forward_ip[1], forward_ip[2], forward_ip[3], args.forward_port });
    std.log.info("Proxy: {}.{}.{}.{}:{}", .{ proxy_ip[0], proxy_ip[1], proxy_ip[2], proxy_ip[3], args.proxy_port });
    std.log.info("TTL: {}", .{args.ttl});

    // Initialize tunnel
    var tunnel = ClientTunnel.init(
        allocator,
        key,
        proxy_ip,
        args.proxy_port,
        forward_ip,
        args.forward_port,
        args.ttl,
    ) catch |err| {
        std.log.err("Failed to initialize tunnel: {}", .{err});
        std.process.exit(1);
    };
    defer tunnel.deinit();

    // Start local listener
    var listener = LocalListener.init(&tunnel, args.local_port) catch |err| {
        std.log.err("Failed to start listener: {}", .{err});
        std.process.exit(1);
    };
    defer listener.deinit();

    listener.run() catch |err| {
        std.log.err("Listener error: {}", .{err});
        std.process.exit(1);
    };
}
