const std = @import("std");

// Import all shared modules for testing
test {
    _ = @import("shared/protocol.zig");
    _ = @import("shared/crypto.zig");
    _ = @import("shared/packet.zig");
    _ = @import("shared/tunnel.zig");
}

test "all tests" {
    std.testing.refAllDecls(@This());
}
