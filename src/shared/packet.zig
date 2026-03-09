const std = @import("std");

/// IPv4 header (20 bytes minimum, without options)
pub const IPv4Header = packed struct {
    version: u4,
    ihl: u4, // Internet Header Length (in 32-bit words)
    dscp: u6,
    ecn: u2,
    total_length: u16,
    identification: u16,
    flags: u3,
    fragment_offset: u13,
    ttl: u8,
    protocol: u8,
    header_checksum: u16,
    source_addr: u32,
    dest_addr: u32,

    pub const MIN_SIZE: usize = 20;
    pub const PROTOCOL_TCP: u8 = 6;

    pub fn getSourceIP(self: *const IPv4Header) [4]u8 {
        return @bitCast(self.source_addr);
    }

    pub fn getDestIP(self: *const IPv4Header) [4]u8 {
        return @bitCast(self.dest_addr);
    }

    pub fn setSourceIP(self: *IPv4Header, ip: [4]u8) void {
        self.source_addr = @bitCast(ip);
    }

    pub fn setDestIP(self: *IPv4Header, ip: [4]u8) void {
        self.dest_addr = @bitCast(ip);
    }

    /// Parse IPv4 header from raw bytes (network byte order)
    pub fn parse(data: []const u8) !IPv4Header {
        if (data.len < MIN_SIZE) return error.PacketTooShort;

        var header: IPv4Header = undefined;
        header.version = @intCast(data[0] >> 4);
        header.ihl = @intCast(data[0] & 0x0F);
        header.dscp = @intCast((data[1] >> 2) & 0x3F);
        header.ecn = @intCast(data[1] & 0x03);
        header.total_length = std.mem.readInt(u16, data[2..4], .big);
        header.identification = std.mem.readInt(u16, data[4..6], .big);
        const flags_frag = std.mem.readInt(u16, data[6..8], .big);
        header.flags = @intCast(flags_frag >> 13);
        header.fragment_offset = @intCast(flags_frag & 0x1FFF);
        header.ttl = data[8];
        header.protocol = data[9];
        header.header_checksum = std.mem.readInt(u16, data[10..12], .big);
        header.source_addr = std.mem.readInt(u32, data[12..16], .big);
        header.dest_addr = std.mem.readInt(u32, data[16..20], .big);

        if (header.version != 4) return error.InvalidVersion;
        if (header.ihl < 5) return error.InvalidHeaderLength;

        return header;
    }

    /// Serialize IPv4 header to bytes (network byte order)
    pub fn serialize(self: *const IPv4Header, buf: []u8) !usize {
        if (buf.len < MIN_SIZE) return error.BufferTooSmall;

        buf[0] = (@as(u8, self.version) << 4) | @as(u8, self.ihl);
        buf[1] = (@as(u8, self.dscp) << 2) | @as(u8, self.ecn);
        std.mem.writeInt(u16, buf[2..4], self.total_length, .big);
        std.mem.writeInt(u16, buf[4..6], self.identification, .big);
        const flags_frag = (@as(u16, self.flags) << 13) | @as(u16, self.fragment_offset);
        std.mem.writeInt(u16, buf[6..8], flags_frag, .big);
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        std.mem.writeInt(u16, buf[10..12], self.header_checksum, .big);
        std.mem.writeInt(u32, buf[12..16], self.source_addr, .big);
        std.mem.writeInt(u32, buf[16..20], self.dest_addr, .big);

        return @as(usize, self.ihl) * 4;
    }
};

/// TCP header (20 bytes minimum, without options)
pub const TCPHeader = packed struct {
    source_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    data_offset: u4, // Header length in 32-bit words
    reserved: u3,
    ns: u1,
    cwr: u1,
    ece: u1,
    urg: u1,
    ack: u1,
    psh: u1,
    rst: u1,
    syn: u1,
    fin: u1,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,

    pub const MIN_SIZE: usize = 20;

    pub fn parse(data: []const u8) !TCPHeader {
        if (data.len < MIN_SIZE) return error.PacketTooShort;

        var header: TCPHeader = undefined;
        header.source_port = std.mem.readInt(u16, data[0..2], .big);
        header.dest_port = std.mem.readInt(u16, data[2..4], .big);
        header.seq_num = std.mem.readInt(u32, data[4..8], .big);
        header.ack_num = std.mem.readInt(u32, data[8..12], .big);
        const data_off_flags = std.mem.readInt(u16, data[12..14], .big);
        header.data_offset = @intCast(data_off_flags >> 12);
        header.reserved = @intCast((data_off_flags >> 9) & 0x07);
        header.ns = @intCast((data_off_flags >> 8) & 0x01);
        header.cwr = @intCast((data[13] >> 7) & 0x01);
        header.ece = @intCast((data[13] >> 6) & 0x01);
        header.urg = @intCast((data[13] >> 5) & 0x01);
        header.ack = @intCast((data[13] >> 4) & 0x01);
        header.psh = @intCast((data[13] >> 3) & 0x01);
        header.rst = @intCast((data[13] >> 2) & 0x01);
        header.syn = @intCast((data[13] >> 1) & 0x01);
        header.fin = @intCast(data[13] & 0x01);
        header.window_size = std.mem.readInt(u16, data[14..16], .big);
        header.checksum = std.mem.readInt(u16, data[16..18], .big);
        header.urgent_pointer = std.mem.readInt(u16, data[18..20], .big);

        if (header.data_offset < 5) return error.InvalidHeaderLength;

        return header;
    }

    pub fn serialize(self: *const TCPHeader, buf: []u8) !usize {
        if (buf.len < MIN_SIZE) return error.BufferTooSmall;

        std.mem.writeInt(u16, buf[0..2], self.source_port, .big);
        std.mem.writeInt(u16, buf[2..4], self.dest_port, .big);
        std.mem.writeInt(u32, buf[4..8], self.seq_num, .big);
        std.mem.writeInt(u32, buf[8..12], self.ack_num, .big);

        const data_off_flags = (@as(u16, self.data_offset) << 12) |
            (@as(u16, self.reserved) << 9) |
            (@as(u16, self.ns) << 8) |
            (@as(u16, self.cwr) << 7) |
            (@as(u16, self.ece) << 6) |
            (@as(u16, self.urg) << 5) |
            (@as(u16, self.ack) << 4) |
            (@as(u16, self.psh) << 3) |
            (@as(u16, self.rst) << 2) |
            (@as(u16, self.syn) << 1) |
            @as(u16, self.fin);
        std.mem.writeInt(u16, buf[12..14], data_off_flags, .big);
        std.mem.writeInt(u16, buf[14..16], self.window_size, .big);
        std.mem.writeInt(u16, buf[16..18], self.checksum, .big);
        std.mem.writeInt(u16, buf[18..20], self.urgent_pointer, .big);

        return @as(usize, self.data_offset) * 4;
    }

    pub fn isSyn(self: *const TCPHeader) bool {
        return self.syn == 1 and self.ack == 0;
    }

    pub fn isSynAck(self: *const TCPHeader) bool {
        return self.syn == 1 and self.ack == 1;
    }

    pub fn isFin(self: *const TCPHeader) bool {
        return self.fin == 1;
    }

    pub fn isRst(self: *const TCPHeader) bool {
        return self.rst == 1;
    }
};

/// Calculate IPv4 header checksum
pub fn checksumIPv4(header_bytes: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;

    while (i + 1 < header_bytes.len) : (i += 2) {
        sum += @as(u32, std.mem.readInt(u16, header_bytes[i..][0..2], .big));
    }

    // Add odd byte if present
    if (header_bytes.len % 2 == 1) {
        sum += @as(u32, header_bytes[header_bytes.len - 1]) << 8;
    }

    // Fold carry bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

/// Calculate TCP checksum with pseudo-header
pub fn checksumTCP(tcp_header: []const u8, payload: []const u8, src_ip: [4]u8, dst_ip: [4]u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header
    sum += @as(u32, std.mem.readInt(u16, src_ip[0..2], .big));
    sum += @as(u32, std.mem.readInt(u16, src_ip[2..4], .big));
    sum += @as(u32, std.mem.readInt(u16, dst_ip[0..2], .big));
    sum += @as(u32, std.mem.readInt(u16, dst_ip[2..4], .big));
    sum += @as(u32, IPv4Header.PROTOCOL_TCP);
    sum += @as(u32, @as(u16, @intCast(tcp_header.len + payload.len)));

    // TCP header (excluding checksum field)
    var i: usize = 0;
    while (i + 1 < tcp_header.len) : (i += 2) {
        if (i == 16) continue; // Skip checksum field
        sum += @as(u32, std.mem.readInt(u16, tcp_header[i..][0..2], .big));
    }

    // Payload
    i = 0;
    while (i + 1 < payload.len) : (i += 2) {
        sum += @as(u32, std.mem.readInt(u16, payload[i..][0..2], .big));
    }

    // Add odd byte if present
    if (payload.len % 2 == 1) {
        sum += @as(u32, payload[payload.len - 1]) << 8;
    }

    // Fold carry bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

/// Rewrite source IP in IPv4 header and recalculate checksums
pub fn rewriteSourceIP(packet: []u8, new_src_ip: [4]u8) !void {
    if (packet.len < IPv4Header.MIN_SIZE) return error.PacketTooShort;

    // Parse IP header
    var ip_header = try IPv4Header.parse(packet);
    const header_len = @as(usize, ip_header.ihl) * 4;

    // Check TCP
    if (packet.len < header_len + TCPHeader.MIN_SIZE) return error.PacketTooShort;

    // Update source IP
    ip_header.setSourceIP(new_src_ip);
    ip_header.header_checksum = 0;
    _ = try ip_header.serialize(packet[0..IPv4Header.MIN_SIZE]);

    // Recalculate IP checksum
    ip_header.header_checksum = checksumIPv4(packet[0..header_len]);
    _ = try ip_header.serialize(packet[0..IPv4Header.MIN_SIZE]);

    // Recalculate TCP checksum
    const tcp_start = header_len;
    const tcp_header = try TCPHeader.parse(packet[tcp_start..]);

    // Zero out TCP checksum for calculation
    std.mem.writeInt(u16, packet[tcp_start + 16 ..][0..2], 0, .big);

    const tcp_header_len = @as(usize, tcp_header.data_offset) * 4;
    const payload = if (packet.len > tcp_start + tcp_header_len)
        packet[tcp_start + tcp_header_len ..]
    else
        packet[0..0];

    const tcp_cksum = checksumTCP(
        packet[tcp_start .. tcp_start + tcp_header_len],
        payload,
        new_src_ip,
        ip_header.getDestIP(),
    );
    std.mem.writeInt(u16, packet[tcp_start + 16 ..][0..2], tcp_cksum, .big);
}

test "IPv4 header parse/serialize" {
    // Sample IPv4 header
    const raw = [_]u8{
        0x45, 0x00, 0x00, 0x28, // version/ihl, dscp/ecn, total length
        0x00, 0x00, 0x40, 0x00, // id, flags/frag
        0x40, 0x06, 0x00, 0x00, // ttl, protocol, checksum (placeholder)
        192, 168, 1, 1, // src IP
        192, 168, 1, 2, // dst IP
    };

    var header = try IPv4Header.parse(&raw);
    try std.testing.expectEqual(@as(u4, 4), header.version);
    try std.testing.expectEqual(@as(u4, 5), header.ihl);
    try std.testing.expectEqual(@as(u8, 64), header.ttl);
    try std.testing.expectEqual(@as(u8, IPv4Header.PROTOCOL_TCP), header.protocol);

    var buf: [20]u8 = undefined;
    _ = try header.serialize(&buf);
    try std.testing.expectEqualSlices(u8, &raw, &buf);
}

test "TCP header parse" {
    const raw = [_]u8{
        0x00, 0x50, // src port (80)
        0x1F, 0x90, // dst port (8080)
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // data offset + flags (SYN)
        0xFF, 0xFF, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent ptr
    };

    var header = try TCPHeader.parse(&raw);
    try std.testing.expectEqual(@as(u16, 80), header.source_port);
    try std.testing.expectEqual(@as(u16, 8080), header.dest_port);
    try std.testing.expect(header.isSyn());
    try std.testing.expect(!header.isFin());
}

test "IPv4 checksum" {
    const raw = [_]u8{
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, // checksum field zero
        192, 168, 1, 1,
        192, 168, 1, 2,
    };

    const checksum = checksumIPv4(&raw);
    // Verify checksum is non-zero
    try std.testing.expect(checksum != 0);
}
