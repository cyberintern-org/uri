const std = @import("std");
const Uri = @This();

// PUBLIC

scheme: ?[]const u8 = null,
raw_fragment: ?[]const u8 = null,

pub const empty = Uri{};

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
};

pub fn parse(s: []const u8) InvalidUriError!Uri {
    return parseInternal(s, false);
}

pub fn parseRequest(s: []const u8) InvalidUriError!Uri {
    return parseInternal(s, true);
}

// PRIVATE

fn parseInternal(s: []const u8, request: bool) InvalidUriError!Uri {
    if (std.mem.indexOfAny(u8, s, &.{ ' ', 0x7f })) |_| return InvalidUriError.InvalidCharacterError;
    if (s.len == 0) return InvalidUriError.EmptyUriError;

    var uri = Uri.empty;
    var rest = s;

    uri.scheme, rest = try getScheme(rest, request);
    rest, uri.raw_fragment = splitEnd(rest, '#');

    return uri;
}

fn getScheme(s: []const u8, request: bool) InvalidUriError!struct { ?[]const u8, []const u8 } {
    l: for (s, 0..) |c, i| switch (c) {
        'A'...'Z', 'a'...'z' => {},
        '0'...'9', '+', '-', '.' => {
            if (i > 0) continue :l;
            if (request) break :l;

            return InvalidUriError.EmptySchemeError;
        },
        ':' => {
            if (i == 0) return InvalidUriError.EmptySchemeError;

            return .{ s[0..i], s[i + 1 ..] };
        },
        else => {
            if (request) break :l;

            return InvalidUriError.EmptySchemeError;
        },
    };

    return .{ null, s };
}

fn splitEnd(s: []const u8, delimiter: u8) struct { []const u8, ?[]const u8 } {
    var iter = std.mem.splitScalar(u8, s, delimiter);

    const first, const rest = .{ iter.first(), iter.rest() };

    return if (rest.len == 0) .{ first, null } else .{ first, rest };
}

// TESTING

const entries = [_]struct { raw: []const u8, uri: Uri }{
    .{
        .raw = "http://example.com/a/b/c?q1=a&q2=b#fragment",
        .uri = Uri{
            .scheme = "http",
            .raw_fragment = "fragment",
        },
    },
};

test "URI parsing" {
    for (entries) |entry| {
        const parsed = try Uri.parse(entry.raw);

        try std.testing.expectEqualSlices(u8, entry.uri.scheme.?, parsed.scheme orelse "");
        try std.testing.expectEqualSlices(u8, entry.uri.raw_fragment orelse "", parsed.raw_fragment orelse "");
    }
}
