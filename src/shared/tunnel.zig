const std = @import("std");
const protocol = @import("protocol.zig");

const SessionState = protocol.SessionState;

/// Represents a client endpoint (IP + port)
pub const Endpoint = struct {
    ip: [4]u8,
    port: u16,

    pub fn init(ip: [4]u8, port: u16) Endpoint {
        return .{ .ip = ip, .port = port };
    }

    pub fn fromAddr(addr: std.net.Address) Endpoint {
        return .{
            .ip = @bitCast(addr.in.sa.addr),
            .port = addr.in.getPort(),
        };
    }

    pub fn toAddress(self: Endpoint) std.net.Address {
        return std.net.Address.initIp4(self.ip, self.port);
    }

    pub fn format(
        self: Endpoint,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try w.print("{}.{}.{}.{}:{}", .{ self.ip[0], self.ip[1], self.ip[2], self.ip[3], self.port });
    }
};

/// TCP 4-tuple identifying a connection
pub const ConnectionId = struct {
    src: Endpoint,
    dst: Endpoint,

    pub fn init(src_ip: [4]u8, src_port: u16, dst_ip: [4]u8, dst_port: u16) ConnectionId {
        return .{
            .src = Endpoint.init(src_ip, src_port),
            .dst = Endpoint.init(dst_ip, dst_port),
        };
    }

    pub fn hash(self: ConnectionId) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&self.src.ip);
        hasher.update(std.mem.asBytes(&self.src.port));
        hasher.update(&self.dst.ip);
        hasher.update(std.mem.asBytes(&self.dst.port));
        return hasher.final();
    }

    pub fn eql(a: ConnectionId, b: ConnectionId) bool {
        return std.mem.eql(u8, &a.src.ip, &b.src.ip) and
            a.src.port == b.src.port and
            std.mem.eql(u8, &a.dst.ip, &b.dst.ip) and
            a.dst.port == b.dst.port;
    }
};

/// Session tracking
pub const Session = struct {
    id: u32,
    conn_id: ConnectionId,
    client_addr: std.net.Address,
    state: SessionState,
    last_activity: i64, // Unix timestamp
    bytes_sent: u64,
    bytes_received: u64,

    pub fn init(
        id: u32,
        conn_id: ConnectionId,
        client_addr: std.net.Address,
    ) Session {
        return .{
            .id = id,
            .conn_id = conn_id,
            .client_addr = client_addr,
            .state = .init,
            .last_activity = std.time.timestamp(),
            .bytes_sent = 0,
            .bytes_received = 0,
        };
    }

    pub fn touch(self: *Session) void {
        self.last_activity = std.time.timestamp();
    }

    pub fn isExpired(self: *const Session, timeout_seconds: i64) bool {
        const now = std.time.timestamp();
        return (now - self.last_activity) > timeout_seconds;
    }
};

/// Session manager with concurrent access support
pub fn SessionManager(comptime _: usize) type {
    return struct {
        const Self = @This();

        sessions: std.AutoHashMap(u32, Session),
        connection_map: std.HashMap(
            ConnectionId,
            u32,
            ConnectionIdContext,
            std.hash_map.default_max_load_percentage,
        ),
        next_id: std.atomic.Value(u32),
        mutex: std.Thread.Mutex,
        allocator: std.mem.Allocator,

        const ConnectionIdContext = struct {
            pub fn hash(self: @This(), key: ConnectionId) u64 {
                _ = self;
                return key.hash();
            }

            pub fn eql(self: @This(), a: ConnectionId, b: ConnectionId) bool {
                _ = self;
                return ConnectionId.eql(a, b);
            }
        };

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .sessions = std.AutoHashMap(u32, Session).init(allocator),
                .connection_map = std.HashMap(
                    ConnectionId,
                    u32,
                    ConnectionIdContext,
                    std.hash_map.default_max_load_percentage,
                ).init(allocator),
                .next_id = std.atomic.Value(u32).init(1),
                .mutex = std.Thread.Mutex{},
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.sessions.deinit();
            self.connection_map.deinit();
        }

        /// Create a new session
        pub fn createSession(
            self: *Self,
            conn_id: ConnectionId,
            client_addr: std.net.Address,
        ) !*Session {
            self.mutex.lock();
            defer self.mutex.unlock();

            // Check if connection already exists
            if (self.connection_map.get(conn_id)) |session_id| {
                if (self.sessions.getPtr(session_id)) |session| {
                    return session;
                }
            }

            const id = self.next_id.fetchAdd(1, .monotonic);
            const session = Session.init(id, conn_id, client_addr);

            try self.sessions.put(id, session);
            try self.connection_map.put(conn_id, id);

            return self.sessions.getPtr(id).?;
        }

        /// Get session by ID
        pub fn getSession(self: *Self, id: u32) ?*Session {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.sessions.getPtr(id);
        }

        /// Get session by connection ID
        pub fn getSessionByConn(self: *Self, conn_id: ConnectionId) ?*Session {
            self.mutex.lock();
            defer self.mutex.unlock();

            const session_id = self.connection_map.get(conn_id) orelse return null;
            return self.sessions.getPtr(session_id);
        }

        /// Remove session
        pub fn removeSession(self: *Self, id: u32) void {
            self.mutex.lock();
            defer self.mutex.unlock();

            if (self.sessions.fetchRemove(id)) |kv| {
                _ = self.connection_map.remove(kv.value.conn_id);
            }
        }

        /// Cleanup expired sessions
        pub fn cleanupExpired(self: *Self, timeout_seconds: i64) usize {
            self.mutex.lock();
            defer self.mutex.unlock();

            var to_remove = std.ArrayList(u32).init(self.allocator);
            defer to_remove.deinit();

            var iter = self.sessions.iterator();
            while (iter.next()) |entry| {
                if (entry.value_ptr.isExpired(timeout_seconds)) {
                    to_remove.append(entry.key_ptr.*) catch continue;
                }
            }

            for (to_remove.items) |id| {
                if (self.sessions.fetchRemove(id)) |kv| {
                    _ = self.connection_map.remove(kv.value.conn_id);
                }
            }

            return to_remove.items.len;
        }

        /// Get session count
        pub fn count(self: *Self) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.sessions.count();
        }
    };
}

test "Session creation and lookup" {
    const gpa = std.testing.allocator;
    var manager = SessionManager(1024).init(gpa);
    defer manager.deinit();

    const conn_id = ConnectionId.init(
        .{ 192, 168, 1, 1 },
        12345,
        .{ 192, 168, 1, 2 },
        80,
    );
    const client_addr = std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 54321);

    const session = try manager.createSession(conn_id, client_addr);
    try std.testing.expectEqual(@as(u32, 1), session.id);
    try std.testing.expect(session.state == .init);

    // Lookup by ID
    const found = manager.getSession(1);
    try std.testing.expect(found != null);
    try std.testing.expectEqual(session.id, found.?.id);

    // Lookup by connection
    const found_by_conn = manager.getSessionByConn(conn_id);
    try std.testing.expect(found_by_conn != null);

    // Remove
    manager.removeSession(1);
    try std.testing.expect(manager.getSession(1) == null);
    try std.testing.expect(manager.count() == 0);
}

test "Session expiration" {
    var session = Session.init(
        1,
        ConnectionId.init(.{ 192, 168, 1, 1 }, 12345, .{ 192, 168, 1, 2 }, 80),
        std.net.Address.initIp4([4]u8{ 10, 0, 0, 1 }, 54321),
    );

    // Should not be expired initially
    try std.testing.expect(!session.isExpired(60));

    // Simulate old activity
    session.last_activity = std.time.timestamp() - 120;
    try std.testing.expect(session.isExpired(60));
}
