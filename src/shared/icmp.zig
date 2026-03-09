const std = @import("std");

/// ICMP Type constants
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// ICMP header structure
pub const ICMPHeader = extern struct {
    type: u8,
    code: u8,
    checksum: u16,
    rest_of_header: u32,
};

/// Parsed ICMP Time Exceeded packet
pub const TimeExceededInfo = struct {
    /// The router that sent the ICMP message
    router_ip: [4]u8,
    /// Original (NAT-translated) source IP from quoted packet
    orig_src_ip: [4]u8,
    /// Original (NAT-translated) source port from quoted packet
    orig_src_port: u16,
    /// Original destination IP from quoted packet
    orig_dst_ip: [4]u8,
    /// Original destination port from quoted packet
    orig_dst_port: u16,
};

/// Parse an ICMP Time Exceeded packet and extract the quoted IP/TCP header
/// Returns the NAT-assigned source IP and port
pub fn parseTimeExceeded(icmp_packet: []const u8, router_ip: [4]u8) ?TimeExceededInfo {
    // ICMP header is 8 bytes minimum
    if (icmp_packet.len < 8) return null;

    const icmp_type = icmp_packet[0];
    const icmp_code = icmp_packet[1];

    // Check if this is a Time Exceeded (TTL expired) message
    if (icmp_type != ICMP_TIME_EXCEEDED or icmp_code != 0) return null;

    // The quoted IP header starts at offset 8 (after ICMP header)
    // RFC 792: "The internet header plus the first 64 bits of the original
    // datagram's data is returned to the source of the error"
    if (icmp_packet.len < 8 + 20 + 8) return null; // ICMP header + IP header + TCP header min

    const quoted_ip_start = 8;

    // Parse quoted IP header
    const version_ihl = icmp_packet[quoted_ip_start];
    const version = version_ihl >> 4;
    const ihl = version_ihl & 0x0F;

    if (version != 4) return null;
    if (ihl < 5) return null;

    const quoted_ip_header_len = @as(usize, ihl) * 4;

    // Check we have enough data for IP + TCP headers
    if (icmp_packet.len < quoted_ip_start + quoted_ip_header_len + 8) return null;

    // Extract source IP from quoted packet (offset 12 in IP header)
    const src_ip_offset = quoted_ip_start + 12;
    const orig_src_ip: [4]u8 = icmp_packet[src_ip_offset..src_ip_offset + 4].*;

    // Extract destination IP from quoted packet (offset 16 in IP header)
    const dst_ip_offset = quoted_ip_start + 16;
    const orig_dst_ip: [4]u8 = icmp_packet[dst_ip_offset..dst_ip_offset + 4].*;

    // Extract source port from quoted TCP header (first 2 bytes after IP header)
    const tcp_start = quoted_ip_start + quoted_ip_header_len;
    const orig_src_port = std.mem.readInt(u16, icmp_packet[tcp_start..][0..2], .big);

    // Extract destination port from quoted TCP header
    const orig_dst_port = std.mem.readInt(u16, icmp_packet[tcp_start + 2 ..][0..2], .big);

    return .{
        .router_ip = router_ip,
        .orig_src_ip = orig_src_ip,
        .orig_src_port = orig_src_port,
        .orig_dst_ip = orig_dst_ip,
        .orig_dst_port = orig_dst_port,
    };
}

/// Calculate ICMP checksum
pub fn calculateChecksum(data: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < data.len) : (i += 2) {
        sum += @as(u32, std.mem.readInt(u16, data[i..][0..2], .big));
    }

    // Add odd byte if present
    if (data.len % 2 == 1) {
        sum += @as(u32, data[data.len - 1]) << 8;
    }

    // Fold carry bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

test "parseTimeExceeded with valid packet" {
    // Construct a minimal ICMP Time Exceeded packet
    var packet: [64]u8 = undefined;
    @memset(&packet, 0);

    // ICMP header
    packet[0] = ICMP_TIME_EXCEEDED; // type
    packet[1] = 0; // code (TTL expired in transit)
    // checksum at 2-3 (skip for test)
    // rest of header at 4-7 (unused for time exceeded)

    // Quoted IP header (starting at offset 8)
    packet[8] = 0x45; // version 4, IHL 5
    // ... other IP fields ...
    // Source IP at offset 20 (8 + 12)
    packet[20] = 192;
    packet[21] = 168;
    packet[22] = 1;
    packet[23] = 100;
    // Dest IP at offset 24 (8 + 16)
    packet[24] = 10;
    packet[25] = 0;
    packet[26] = 0;
    packet[27] = 1;

    // Quoted TCP header (starting at offset 28 = 8 + 20)
    std.mem.writeInt(u16, packet[28..30], 12345, .big); // src port
    std.mem.writeInt(u16, packet[30..32], 80, .big); // dst port

    const info = parseTimeExceeded(&packet, .{ 10, 0, 0, 1 });
    try std.testing.expect(info != null);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 100 }, &info.?.orig_src_ip);
    try std.testing.expectEqual(@as(u16, 12345), info.?.orig_src_port);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 0, 1 }, &info.?.orig_dst_ip);
    try std.testing.expectEqual(@as(u16, 80), info.?.orig_dst_port);
}
