const std = @import("std");

/// Protocol magic bytes for identification
pub const MAGIC = [_]u8{ 0xF9, 0x1A, 0x2B, 0x3C };

/// Protocol version
pub const VERSION: u8 = 1;

/// Packet types
pub const PacketType = enum(u8) {
    data = 0x01,
    connect = 0x02,
    disconnect = 0x03,
    keepalive = 0x04,
    ack = 0x05,
};

/// Tunnel header prepended to each UDP payload
/// Format: [MAGIC(4)][VERSION(1)][TYPE(1)][SESSION_ID(4)][CHECKSUM(2)][PAYLOAD_LENGTH(2)]
pub const TunnelHeader = struct {
    magic: [4]u8,
    version: u8,
    packet_type: PacketType,
    session_id: u32,
    checksum: u16,
    payload_length: u16,

    pub const SIZE: usize = 14;

    pub fn init(session_id: u32, packet_type: PacketType, payload_length: u16) TunnelHeader {
        return .{
            .magic = MAGIC,
            .version = VERSION,
            .packet_type = packet_type,
            .session_id = session_id,
            .checksum = 0,
            .payload_length = payload_length,
        };
    }

    pub fn serialize(self: *const TunnelHeader) [SIZE]u8 {
        var buf: [SIZE]u8 = undefined;
        @memcpy(buf[0..4], &self.magic);
        buf[4] = self.version;
        buf[5] = @intFromEnum(self.packet_type);
        std.mem.writeInt(u32, buf[6..10], self.session_id, .big);
        std.mem.writeInt(u16, buf[10..12], self.checksum, .big);
        std.mem.writeInt(u16, buf[12..14], self.payload_length, .big);
        return buf;
    }

    pub fn deserialize(buf: *const [SIZE]u8) TunnelHeader {
        var header: TunnelHeader = undefined;
        @memcpy(&header.magic, buf[0..4]);
        header.version = buf[4];
        header.packet_type = @enumFromInt(buf[5]);
        header.session_id = std.mem.readInt(u32, buf[6..10], .big);
        header.checksum = std.mem.readInt(u16, buf[10..12], .big);
        header.payload_length = std.mem.readInt(u16, buf[12..14], .big);
        return header;
    }

    pub fn isValid(self: *const TunnelHeader) bool {
        return std.mem.eql(u8, &self.magic, &MAGIC) and self.version == VERSION;
    }
};

/// Session state
pub const SessionState = enum(u8) {
    init,
    connecting,
    established,
    closing,
    closed,
};

/// Calculate header checksum (simple sum complement)
pub fn calculateChecksum(header: *const TunnelHeader, payload: []const u8) u16 {
    var sum: u32 = 0;

    // Sum header bytes (excluding checksum field)
    const serialized = header.serialize();
    for (serialized[0..10]) |byte| {
        sum += @as(u32, byte);
    }
    for (serialized[12..14]) |byte| {
        sum += @as(u32, byte);
    }

    // Sum payload bytes
    for (payload) |byte| {
        sum += @as(u32, byte);
    }

    // Fold to 16 bits
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return @truncate(~sum);
}

test "TunnelHeader serialization roundtrip" {
    const header = TunnelHeader.init(0x12345678, .data, 100);
    const serialized = header.serialize();
    const deserialized = TunnelHeader.deserialize(&serialized);

    try std.testing.expectEqual(@as(u32, 0x12345678), deserialized.session_id);
    try std.testing.expectEqual(PacketType.data, deserialized.packet_type);
    try std.testing.expectEqual(@as(u16, 100), deserialized.payload_length);
    try std.testing.expect(deserialized.isValid());
}

test "TunnelHeader validation" {
    var header = TunnelHeader.init(1, .data, 0);
    try std.testing.expect(header.isValid());

    header.magic[0] = 0x00;
    try std.testing.expect(!header.isValid());
}

test "Checksum calculation" {
    const header = TunnelHeader.init(1, .data, 5);
    const payload = [_]u8{ 1, 2, 3, 4, 5 };
    const checksum = calculateChecksum(&header, &payload);
    try std.testing.expect(checksum != 0);
}
