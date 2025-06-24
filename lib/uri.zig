const std = @import("std");
const Uri = @This();

// PUBLIC

scheme: ?[]const u8 = null,
raw_query: ?[]const u8 = null,
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

    if (rest.len > 1 and rest[rest.len - 1] == '?') rest = rest[0 .. rest.len - 1];
    rest, uri.raw_query = splitEnd(rest, '?');

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

const uri_entries = [_]struct { raw: []const u8, uri: Uri }{
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#top",
        .uri = Uri{
            .scheme = "https",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = "top",
        },
    },
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#:~:text=whatever",
        .uri = Uri{
            .scheme = "https",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = ":~:text=whatever",
        },
    },
    .{
        .raw = "ldap://[2001:db8::7]/c=GB?objectClass?one",
        .uri = Uri{
            .scheme = "ldap",
            .raw_query = "objectClass?one",
            .raw_fragment = null,
        },
    },
    .{
        .raw = "mailto:John.Doe@example.com",
        .uri = Uri{
            .scheme = "mailto",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
    .{
        .raw = "news:comp.infosystems.www.servers.unix",
        .uri = Uri{
            .scheme = "news",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
    .{
        .raw = "tel:+1-816-555-1212",
        .uri = Uri{
            .scheme = "tel",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
    .{
        .raw = "telnet://192.0.2.16:80/",
        .uri = Uri{
            .scheme = "telnet",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
    .{
        .raw = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        .uri = Uri{
            .scheme = "urn",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
    .{
        .raw = "file:///etc/passwd",
        .uri = Uri{
            .scheme = "file",
            .raw_query = null,
            .raw_fragment = null,
        },
    },
};

test "URI parsing" {
    for (uri_entries) |entry| {
        const parsed = try Uri.parse(entry.raw);

        try std.testing.expectEqualStrings(entry.uri.scheme.?, parsed.scheme orelse "");
        try std.testing.expectEqualStrings(entry.uri.raw_query orelse "", parsed.raw_query orelse "");
        try std.testing.expectEqualStrings(entry.uri.raw_fragment orelse "", parsed.raw_fragment orelse "");
    }
}
