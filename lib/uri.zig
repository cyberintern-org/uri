const std = @import("std");
const Uri = @This();

// PUBLIC

scheme: ?[]const u8 = null,

pub const empty = Uri{};

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
};

pub const Segment = struct {
    raw: []const u8 = "",

    pub const empty = Segment{};
};

pub fn parse(s: []const u8) !Uri {
    return parseInternal(s, false);
}

pub fn parseRequest(s: []const u8) !Uri {
    return parseInternal(s, true);
}

// PRIVATE

fn parseInternal(s: []const u8, request: bool) !Uri {
    if (std.mem.indexOfAny(u8, s, &.{ ' ', 0x7f })) |_| return InvalidUriError.InvalidCharacterError;
    if (s.len == 0) return InvalidUriError.EmptyUriError;

    _ = request;
    return Uri.empty;
}

// TESTING

const entries = [_]struct { raw: []const u8, uri: Uri }{
    .{ .raw = "http://example.com/a/b/c?q1=a&q2=b#fragment", .uri = Uri.empty },
};

test "URI parsing" {
    for (entries) |entry| {
        const parsed = try Uri.parse(entry.raw);
        _ = parsed;
    }
}
