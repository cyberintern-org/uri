// libwww/uri - URI parsing, production and normalization implementation for the WWW cyberintern workgroup
// Copyright (C) 2025 [Cybernetic Internetionale](https://cyberintern.org)
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
// USA

const std = @import("std");
const uri = @import("../uri.zig");
const UriRef = uri.UriRef;
const HostType = uri.HostType;

// API

pub const ParseError = error{
    InvalidEncoding,
    InvalidFormat,
    UnexpectedCharacter,
};

pub fn parse(s: []const u8) ParseError!UriRef {
    var out: UriRef = .{};
    var rest = s;

    scheme: for (s, 0..) |c, i| switch (c) {
        'A'...'Z', 'a'...'z' => {},
        '0'...'9', '+', '-', '.' => if (i == 0) break :scheme,
        ':' => if (i == 0) return ParseError.InvalidFormat else {
            out.scheme = s[0..i];
            rest = s[i + 1 ..];
            break :scheme;
        },
        else => break :scheme,
    };

    if (std.mem.startsWith(u8, rest, "//")) authority: {
        out.host = "";
        out.host_type = HostType.domain;
        rest = rest[2..];

        if (rest.len == 0 or rest[0] == '/' or rest[0] == '?' or rest[0] == '#') {
            break :authority;
        }

        if (std.mem.indexOfScalar(u8, @constCast(&std.mem.splitScalar(u8, rest, '/')).first(), '@') != null) {
            var i: usize = 0;

            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in userinfo
                    i += 2;
                },
                '@' => {
                    out.userinfo = rest[0..i];
                    rest = rest[i + 1 ..];
                    break;
                },
                else => switch (classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalid character in userinfo
                },
            };
        }

        out.host_type = switch (rest[0]) {
            '[' => iplit: {
                rest = rest[1..];
                if (rest.len == 0) return ParseError.InvalidFormat; // empty IPv6/IPvFuture, trailing '['
                if (rest[0] != 'v') break :iplit .ipv6;
                rest = rest[1..];
                break :iplit .ipvfuture;
            },
            '0'...'9' => .ipv4,
            else => .domain,
        };

        parser: switch (out.host_type.?) {
            .ipvfuture => {
                var found_dot = false;
                var found_second = false;

                for (rest, 0..) |c, i| switch (c) {
                    '.' => {
                        if (i == 0) return ParseError.InvalidFormat; // empty first part
                        if (found_dot) return ParseError.InvalidFormat; // too many parts
                        found_dot = true;
                    },
                    ']' => {
                        if (!found_dot or !found_second) return ParseError.InvalidFormat; // not enough parts
                        out.host = rest[0..i];
                        rest = rest[i + 1 ..];
                        break :parser;
                    },
                    'A'...'F', 'a'...'f', '0'...'9' => found_second = found_dot,
                    ':' => if (!found_dot) return ParseError.InvalidFormat, // ':' can appear only in the second part
                    else => {
                        if (!found_dot) return ParseError.InvalidFormat; // characters other than HEXDIG can only appear in the second part
                        switch (classify(c)) {
                            .unreserved, .sub_delim => {},
                            .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalid character in IPvFuture
                        }
                    },
                };

                return ParseError.InvalidFormat; // doesn't end in ']'
            },
            .ipv6 => {
                var left_parts: usize = 0;
                var right_parts: usize = 0;
                var len: usize = 0;
                var colons: usize = 0;
                var in_right = false;
                var in_ls32 = false;

                var i: usize = 0;
                l: while (i < rest.len) : (i += 1) switch (rest[i]) {
                    ']' => {
                        if (colons == 1) return ParseError.InvalidFormat; // must end with 0 or 2 colons
                        if (left_parts + right_parts > 7) return ParseError.InvalidFormat; // too many parts
                        out.host = rest[0..i];
                        rest = if (i < rest.len - 1) rest[i + 1 ..] else "";
                        break :parser;
                    },
                    '%' => {
                        if (colons == 1) return ParseError.InvalidFormat; // must end with 0 or 2 colons
                        if (left_parts + right_parts > 7) return ParseError.InvalidFormat; // too many parts
                        out.host = rest[0..i];
                        rest = rest[i..];
                        break :l;
                    },
                    ':' => switch (colons) {
                        0 => {
                            len = 0;
                            colons += 1;
                        },
                        1 => {
                            if (in_right) return ParseError.InvalidFormat; // double colon in right part
                            if (left_parts > 4) in_right = true else in_ls32 = true;
                            colons += 1;
                        },
                        else => return ParseError.InvalidFormat, // too many colons
                    },
                    '0'...'9', 'A'...'F', 'a'...'f' => {
                        if (len == 0) {
                            if (in_right) right_parts += 1 else left_parts += 1;
                        }
                        colons = 0;
                        len += 1;
                    },
                    '.' => {
                        if (left_parts + right_parts > 7) return ParseError.InvalidFormat; // too many parts
                        i = std.mem.lastIndexOfScalar(u8, rest[0..i], ':') orelse return ParseError.InvalidFormat; // l32 with dot must be after last colon
                        i += try parseIpv4(rest[i + 1 ..], true);
                        out.host = rest[0..i];
                    },
                    else => return ParseError.InvalidFormat, // invalid character in IPv6
                };

                if (rest.len > 0 and rest[0] == '%') {
                    if (rest.len < 4) return ParseError.InvalidFormat; // must be at least 4 characters (%25 + at least 1 pct-encoded / unreserved character)
                    if (rest[0] != '%' or rest[1] != '2' or rest[2] != '5') return ParseError.InvalidFormat; // must start with %25

                    i = 3;
                    while (i < rest.len) : (i += 1) switch (rest[i]) {
                        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', '~' => {},
                        '%' => {
                            try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in zone ID
                            i += 2;
                        },
                        ']' => {
                            out.zone_id = rest[3..i];
                            rest = rest[i + 1 ..];
                            break :parser;
                        },
                        else => return ParseError.InvalidFormat, // invalid character in zone ID
                    };
                }

                return ParseError.InvalidFormat; // doesn't end in ']'
            },
            .ipv4 => {
                const host_end = parseIpv4(rest, false) catch {
                    out.host_type = .domain; // if it fails, we assume it's a reg-name
                    continue :parser .domain;
                };
                out.host = rest[0..host_end];
                rest = if (host_end == rest.len) "" else rest[host_end..];
            },
            .domain => {
                var i: usize = 0;

                while (i < rest.len) : (i += 1) switch (rest[i]) {
                    '%' => {
                        try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in reg name
                        i += 2;
                    },
                    ':', '/', '?', '#' => {
                        out.host = rest[0..i];
                        rest = rest[i..];
                        break :parser;
                    },
                    else => switch (classify(rest[i])) {
                        .unreserved, .sub_delim => {},
                        .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalidd character in reg name
                    },
                };

                out.host = rest;
                rest = "";
            },
        }

        if (rest.len > 0 and rest[0] == ':') port: {
            rest = rest[1..];

            for (rest, 0..) |c, i| switch (c) {
                '0'...'9' => {
                    out.port = (out.port orelse 0) * 10 + (c - '0');
                },
                '/', '?', '#' => {
                    rest = rest[i..];
                    break :port;
                },
                else => return ParseError.UnexpectedCharacter, // invalid character in port
            };

            rest = "";
        }
    }

    if (rest.len > 0) parser: switch (rest[0]) {
        '?' => {
            rest = rest[1..];

            var i: usize = 0;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':', '/', '?', '@' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in query
                    i += 2;
                },
                '#' => {
                    out.query = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser '#';
                },
                else => switch (classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalid character in query
                },
            };

            out.query = rest;
        },
        '#' => {
            rest = rest[1..];

            var i: usize = 0;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':', '/', '?', '@', '#' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in fragment
                    i += 2;
                },
                else => switch (classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalid character in fragment
                },
            };

            out.fragment = rest;
        },
        else => {
            var validated_path_noscheme = out.scheme != null or rest[0] == ':';

            var i: usize = 0;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':' => if (!validated_path_noscheme) return ParseError.InvalidFormat, // ':' in first path part (when in path-noscheme)
                '@' => {},
                '/' => validated_path_noscheme = true,
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]); // invalid pct-encoding in path
                    i += 2;
                },
                '?', '#' => {
                    out.path = rest[0..i];
                    const c = rest[i];
                    rest = rest[i..];
                    continue :parser c;
                },
                else => switch (classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim, .unknown => return ParseError.UnexpectedCharacter, // invalid character in path
                },
            };

            out.path = rest;
        },
    };

    return out;
}

// INTERNAL

inline fn parseIpv4(s: []const u8, comptime ipv6: bool) ParseError!usize {
    var parts: usize = 0;
    var len: usize = 0;

    for (s, 0..) |c, i| switch (c) {
        '.' => {
            if (len == 0) return ParseError.InvalidFormat; // empty part
            parts += 1;
            len = 0;
        },
        ':', '/', '?', '#' => {
            if (ipv6) return ParseError.InvalidFormat; // must end with ]
            if (len == 0) return ParseError.InvalidFormat; // empty part
            if (parts != 3) return ParseError.InvalidFormat; // too many / not enough parts
            return i;
        },
        ']', '%' => {
            if (!ipv6) return ParseError.InvalidFormat; // only valid when ipv4 is a l32 of ipv6
            if (len == 0) return ParseError.InvalidFormat; // empty part
            if (parts != 3) return ParseError.InvalidFormat; // too many / not enough parts
            return i;
        },
        '0'...'9' => {
            if (len > 3) return ParseError.InvalidFormat; // too long part

            switch (len) {
                0 => {}, // first digit, we ignore it for now
                1 => if (s[i - 1] == '0') return ParseError.InvalidFormat, // leading zero
                2 => switch (s[i - 2]) {
                    '1' => {}, // 100 - 199
                    '2' => switch (s[i - 1]) {
                        '0'...'4' => {}, // 200 - 249
                        '5' => if (c > '5') return ParseError.InvalidFormat, // 250 - 255
                        else => return ParseError.InvalidFormat, // > 255
                    },
                    else => return ParseError.InvalidFormat, // >= 300
                },
                else => unreachable,
            }

            len += 1;
        },
        else => return ParseError.InvalidFormat,
    };

    if (parts != 3 or len == 0) return ParseError.InvalidFormat;
    return s.len;
}

inline fn classify(c: u8) enum { unknown, unreserved, sub_delim, gen_delim } {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', '~' => .unreserved,
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => .sub_delim,
        ':', '/', '?', '#', '[', ']', '@' => .gen_delim,
        else => .unknown,
    };
}

inline fn validatePctEncoding(s: []const u8) error{InvalidEncoding}!void {
    if (s.len < 2 or !std.ascii.isHex(s[0]) or !std.ascii.isHex(s[1])) return ParseError.InvalidEncoding;
}

// TESTS

const parsing_checks = [_]struct { in: []const u8, out: UriRef }{
    .{ // URI, authority, path-empty
        .in = "http://example.com",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "",
        },
    },
    .{ // URI, authority, path-absolute
        .in = "http://example.com/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
        },
    },
    .{ // path with percent-encoding
        .in = "http://example.com/path/to/resource%20with%20spaces",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource%20with%20spaces",
        },
    },
    .{ // fragment with percent-encoding
        .in = "http://example.com/path#fragment%20with%20spaces",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .fragment = "fragment%20with%20spaces",
        },
    },
    .{ // userinfo
        .in = "http://user@example.com",
        .out = UriRef{
            .scheme = "http",
            .userinfo = "user",
            .host = "example.com",
            .host_type = .domain,
            .path = "",
        },
    },
    .{ // userinfo with percent-encoding
        .in = "http://user%20name@example.com",
        .out = UriRef{
            .scheme = "http",
            .userinfo = "user%20name",
            .host = "example.com",
            .host_type = .domain,
            .path = "",
        },
    },
    .{ // empty query
        .in = "http://example.com/path?",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .query = "",
        },
    },
    .{ // query with percent-encoding
        .in = "http://example.com/path?query%20with%20spaces",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .query = "query%20with%20spaces",
        },
    },
    .{ // query with question mark
        .in = "http://example.com/path?query=with?question",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .query = "query=with?question",
        },
    },
    .{ // no authority, path-rootless
        .in = "mailto:john.doe@example.com",
        .out = UriRef{
            .scheme = "mailto",
            .path = "john.doe@example.com",
        },
    },
    .{ // empty authority, path-abempty
        .in = "file:///path/to/file.txt",
        .out = UriRef{
            .scheme = "file",
            .host = "",
            .host_type = .domain,
            .path = "/path/to/file.txt",
        },
    },
    .{ // no authority, path-absolute
        .in = "http:/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .path = "/path/to/resource",
        },
    },
    .{ // no authority, path-empty
        .in = "http:",
        .out = UriRef{
            .scheme = "http",
        },
    },
    .{ // no authority, path looking like one
        .in = "http:example.com/?query",
        .out = UriRef{
            .scheme = "http",
            .path = "example.com/",
            .query = "query",
        },
    },
    .{ // unescaped :// in query should not create a scheme
        .in = "http://example.com/path?from=http://example.com",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .query = "from=http://example.com",
        },
    },
    .{ // leading // without scheme should create an authority
        .in = "//example.com/path/to/resource",
        .out = UriRef{
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
        },
    },
    .{ // leading // without scheme, with userinfo, path, and query
        .in = "//user@example.com/path/to/resource?query=value",
        .out = UriRef{
            .userinfo = "user",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
            .query = "query=value",
        },
    },
    .{ // IPv4 address in authority
        .in = "http://192.168.0.1/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "192.168.0.1",
            .host_type = .ipv4,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv4 and port in authority
        .in = "http://192.168.0.1:8080/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "192.168.0.1",
            .host_type = .ipv4,
            .port = 8080,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv6 address in authority
        .in = "http://[2001:db8::1]/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "2001:db8::1",
            .host_type = .ipv6,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv6 address with zone ID in authority
        .in = "http://[2001:db8::1%25eth0]/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "2001:db8::1",
            .host_type = .ipv6,
            .zone_id = "eth0",
            .path = "/path/to/resource",
        },
    },
    .{ // IPv6 address with IPv4 as last part
        .in = "http://[2001:db8::192.168.0.1]/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "2001:db8::192.168.0.1",
            .host_type = .ipv6,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv6 address with IPv4, zone ID and port
        .in = "http://[2001:db8::192.168.0.1%25eth0]:8080/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "2001:db8::192.168.0.1",
            .host_type = .ipv6,
            .zone_id = "eth0",
            .port = 8080,
            .path = "/path/to/resource",
        },
    },
    .{ // reg-name with sub-delims
        .in = "mysql://a,b,c/default",
        .out = UriRef{
            .scheme = "mysql",
            .host = "a,b,c",
            .host_type = .domain,
            .path = "/default",
        },
    },
    .{ // empty port
        .in = "http://example.com:/path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
        },
    },
    .{ // path with two leeading slashes
        .in = "http://example.com//path/to/resource",
        .out = UriRef{
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "//path/to/resource",
        },
    },
    .{ // magnet path with two leading slashes
        .in = "magnet://?xt=urn:btih:1234567890abcdef1234567890abcdef12345678&dn=example",
        .out = UriRef{
            .scheme = "magnet",
            .host = "",
            .host_type = .domain,
            .path = "",
            .query = "xt=urn:btih:1234567890abcdef1234567890abcdef12345678&dn=example",
        },
    },
};

comptime {
    for (parsing_checks) |entry| {
        _ = struct {
            test {
                const parsed = try parse(entry.in);

                if (entry.out.scheme) |scheme| {
                    try std.testing.expect(parsed.scheme != null);
                    try std.testing.expectEqualStrings(scheme, parsed.scheme.?);
                } else {
                    try std.testing.expectEqual(null, parsed.scheme);
                }

                if (entry.out.userinfo) |userinfo| {
                    try std.testing.expect(parsed.userinfo != null);
                    try std.testing.expectEqualStrings(userinfo, parsed.userinfo.?);
                } else {
                    try std.testing.expectEqual(null, parsed.userinfo);
                }

                if (entry.out.host_type) |host_type| {
                    try std.testing.expect(parsed.host_type != null);
                    try std.testing.expectEqual(host_type, parsed.host_type.?);
                } else {
                    try std.testing.expectEqual(null, parsed.host_type);
                }

                if (entry.out.host) |host| {
                    try std.testing.expect(parsed.host != null);
                    try std.testing.expectEqualStrings(host, parsed.host.?);
                } else {
                    try std.testing.expectEqual(null, parsed.host);
                }

                if (entry.out.zone_id) |zone_id| {
                    try std.testing.expect(parsed.zone_id != null);
                    try std.testing.expectEqualStrings(zone_id, parsed.zone_id.?);
                } else {
                    try std.testing.expectEqual(null, parsed.zone_id);
                }

                if (entry.out.port) |port| {
                    try std.testing.expect(parsed.port != null);
                    try std.testing.expectEqual(port, parsed.port.?);
                } else {
                    try std.testing.expectEqual(null, parsed.port);
                }

                try std.testing.expectEqualStrings(entry.out.path, parsed.path);

                if (entry.out.query) |query| {
                    try std.testing.expect(parsed.query != null);
                    try std.testing.expectEqualStrings(query, parsed.query.?);
                } else {
                    try std.testing.expectEqual(null, parsed.query);
                }

                if (entry.out.fragment) |fragment| {
                    try std.testing.expect(parsed.fragment != null);
                    try std.testing.expectEqualStrings(fragment, parsed.fragment.?);
                } else {
                    try std.testing.expectEqual(null, parsed.fragment);
                }
            }
        };
    }
}
