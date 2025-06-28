const std = @import("std");
const uri = @import("root.zig");

// API

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
    ExpectedUriError,
};

pub fn parseUri(s: []const u8) InvalidUriError!uri.Uri {
    const parsed = try uri.parseAny(s);
    return switch (parsed) {
        .uri => |u| u,
        .relative_ref => return InvalidUriError.ExpectedUriError,
    };
}

pub fn parseAny(s: []const u8) InvalidUriError!uri.UriRef {
    if (s.len == 0) return InvalidUriError.EmptyUriError;
    if (std.mem.indexOfAny(u8, s, &.{ ' ', 0x7f })) |_| return InvalidUriError.InvalidCharacterError;

    var out = uri.UriRef{ .uri = uri.Uri{} };
    var rest = s;

    const scheme, rest = try getScheme(rest);
    if (scheme) |sch| {
        out.uri.scheme = sch;
    } else {
        out = uri.UriRef{ .relative_ref = uri.RelativeRef{} };
    }

    return out;
}

// INTERNAL

fn getScheme(s: []const u8) InvalidUriError!struct { ?[]const u8, []const u8 } {
    l: for (s, 0..) |c, i| switch (c) {
        'A'...'Z', 'a'...'z' => {},
        '0'...'9', '+', '-', '.' => if (i == 0) break :l,
        ':' => return if (i == 0) InvalidUriError.EmptySchemeError else .{ s[0..i], s[i + 1 ..] },
        else => break :l,
    };

    return .{ null, s };
}

fn splitEnd(s: []const u8, delimiter: u8) struct { []const u8, ?[]const u8 } {
    var iter = std.mem.splitScalar(u8, s, delimiter);

    const first, const rest = .{ iter.first(), iter.rest() };

    return if (rest.len == 0) .{ first, null } else .{ first, rest };
}

// TESTS

const uri_entries = [_]struct { raw: []const u8, parsed: uri.Uri }{
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#top",
        .parsed = uri.Uri{
            .scheme = "https",
        },
    },
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#:~:text=whatever",
        .parsed = uri.Uri{
            .scheme = "https",
        },
    },
    .{
        .raw = "ldap://[2001:db8::7]/c=GB?objectClass?one",
        .parsed = uri.Uri{
            .scheme = "ldap",
        },
    },
    .{
        .raw = "mailto:John.Doe@example.com",
        .parsed = uri.Uri{
            .scheme = "mailto",
        },
    },
    .{
        .raw = "news:comp.infosystems.www.servers.unix",
        .parsed = uri.Uri{
            .scheme = "news",
        },
    },
    .{
        .raw = "tel:+1-816-555-1212",
        .parsed = uri.Uri{
            .scheme = "tel",
        },
    },
    .{
        .raw = "telnet://192.0.2.16:80/",
        .parsed = uri.Uri{
            .scheme = "telnet",
        },
    },
    .{
        .raw = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        .parsed = uri.Uri{
            .scheme = "urn",
        },
    },
    .{
        .raw = "file:///etc/passwd",
        .parsed = uri.Uri{
            .scheme = "file",
        },
    },
};

test "URI parsing" {
    for (uri_entries) |entry| {
        const parsed = try parseUri(entry.raw);

        try std.testing.expectEqualStrings(entry.parsed.scheme, parsed.scheme);
    }
}
