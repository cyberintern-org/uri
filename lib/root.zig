const std = @import("std");

pub const Uri = @import("uri.zig");

test {
    std.testing.refAllDecls(@This());
}
