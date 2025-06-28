const std = @import("std");
const parsing = @import("parsing.zig");

pub const UriRef = union(enum) {
    uri: Uri,
    relative_ref: RelativeRef,
};

pub const Uri = struct {
    scheme: []const u8 = "",
    raw_query: ?[]const u8 = null,
    raw_fragment: ?[]const u8 = null,
};

pub const RelativeRef = struct {};

pub const InvalidUriError = parsing.InvalidUriError;
pub const parseUri = parsing.parseUri;
pub const parseAny = parsing.parseAny;

test {
    std.testing.refAllDecls(@This());
}
