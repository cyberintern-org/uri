const std = @import("std");

pub const Kind = enum {
    uri,
    relative_ref,
};

pub const UriRef = struct {
    scheme: ?[]const u8 = null,
    path: []const u8 = "",
    raw_query: ?[]const u8 = null,
    raw_fragment: ?[]const u8 = null,

    kind: Kind = .relative_ref,
};

pub const parsing = @import("parsing.zig");

test {
    std.testing.refAllDecls(@This());
}
