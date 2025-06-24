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

// TESTING

const entries = [_]struct { raw: []const u8, uri: Uri }{
    .{
        .raw = "http://example.com/a/b/c?q1=a&q2=b#fragment",
        .uri = Uri{
            .scheme = "http",
        },
    },
};

test "URI parsing" {
    for (entries) |entry| {
        const parsed = try Uri.parse(entry.raw);

        std.testing.expectEqualSlices(u8, entry.uri.scheme.?, parsed.scheme orelse "");
    }
}
