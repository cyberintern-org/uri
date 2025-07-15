// liburi - URI parsing, production and normalization implementation for the www cyberintern work
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
const root = @import("root.zig");
const UriRef = root.UriRef;
const Kind = root.Kind;
const HostType = root.HostType;

// API

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
    InvalidHostError,
    InvalidPortError,
    InvalidPathNoschemeError,
    InvalidPathError,
    InvalidQueryError,
    InvalidFragmentError,
};

pub fn parse(s: []const u8) InvalidUriError!UriRef {
    if (s.len == 0) return InvalidUriError.EmptyUriError;

    var out: UriRef = .{ .raw = s };
    var rest = s;

    var rest_cache = s;
    var i_cache: usize = 0;

    parser: switch (ParsingState.scheme) {
        .scheme => {
            for (rest, 0..) |c, i| switch (c) {
                'A'...'Z', 'a'...'z' => {},
                '0'...'9', '+', '-', '.' => if (i == 0) break,
                ':' => if (i == 0) return InvalidUriError.EmptySchemeError else {
                    out.kind = .uri;
                    out.scheme = s[0..i];
                    rest = s[i + 1 ..];
                    continue :parser .authority_start;
                },
                else => break,
            };
            out.kind = .relative_ref;
            continue :parser .authority_start;
        },
        .authority_start => if (!std.mem.startsWith(u8, rest, "//")) continue :parser .path else {
            rest = rest[2..];
            continue :parser .authority;
        },
        .authority => {
            out.host = "";
            out.host_type = .domain;
            if (rest.len > 0) switch (rest[0]) {
                '[' => {
                    rest = rest[1..];
                    if (rest.len == 0) return InvalidUriError.InvalidHostError;
                    if (rest[0] == 'v') {
                        out.host_type = .ipvfuture;
                        rest = rest[1..];
                        continue :parser .host_ipvfuture;
                    }
                    out.host_type = .ipv6;
                    continue :parser .host_ipv6;
                },
                '0'...'9' => {
                    out.host_type = .ipv4;
                    continue :parser .host_ipv4;
                },
                '/' => continue :parser .path,
                else => continue :parser .host_regname,
            };
        },
        .host_ipvfuture => {
            var found_dot = false;
            var found_second = false;

            for (rest, 0..) |c, i| switch (c) {
                '.' => {
                    if (found_dot or i == 0) return InvalidUriError.InvalidHostError;
                    found_dot = true;
                },
                ']' => {
                    if (!found_dot or !found_second) return InvalidUriError.InvalidHostError;
                    out.host = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser .host_end;
                },
                'A'...'F', 'a'...'f', '0'...'9' => {
                    if (found_dot) {
                        found_second = true;
                    }
                },
                else => {
                    if (!found_dot) return InvalidUriError.InvalidHostError;
                    if (c == ':') continue;
                    switch (try classify(c)) {
                        .unreserved, .sub_delim => {},
                        .gen_delim => return InvalidUriError.InvalidHostError,
                    }
                },
            };

            return InvalidUriError.InvalidHostError;
        },
        .host_ipv6 => {
            var left_parts: usize = 0;
            var right_parts: usize = 0;
            var len: usize = 0;
            var colons: usize = 0;
            var in_right = false;
            var in_ls32 = false;

            for (rest, 0..) |c, i| switch (c) {
                ']' => {
                    if (colons == 1) return InvalidUriError.InvalidHostError; // must end with 0 or 2 colons
                    if (left_parts + right_parts > 7) return InvalidUriError.InvalidHostError; // too many parts
                    out.host = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser .host_end;
                },
                ':' => switch (colons) {
                    0 => {
                        len = 0;
                        colons += 1;
                    },
                    1 => {
                        if (in_right) return InvalidUriError.InvalidHostError; // double colon in right part
                        if (left_parts > 4) in_right = true else in_ls32 = true;
                        colons += 1;
                    },
                    else => return InvalidUriError.InvalidHostError, // too many colons
                },
                '0'...'9', 'A'...'F', 'a'...'f' => {
                    if (len == 0) {
                        if (in_right) right_parts += 1 else left_parts += 1;
                    }
                    colons = 0;
                    len += 1;
                },
                '.' => {
                    if (left_parts + right_parts > 7) return InvalidUriError.InvalidHostError; // too many parts
                    i_cache = std.mem.lastIndexOfScalar(u8, rest[0..i], ':') orelse return InvalidUriError.InvalidHostError; // l32 with dot must be after last colon
                    i_cache += 1;
                    rest_cache = rest;
                    rest = rest[i_cache..];
                    continue :parser .host_ipv4;
                },
                '%' => {
                    if (left_parts + right_parts > 7) return InvalidUriError.InvalidHostError; // too many parts
                    out.host = rest[0..i];
                    rest = rest[i..];
                    continue :parser .zone_id;
                },
                else => return InvalidUriError.InvalidHostError, // invalid character
            };
        },
        .host_ipv4 => {
            var parts: usize = 0;
            var len: usize = 0;

            for (rest, 0..) |c, i| switch (c) {
                '.' => {
                    if (i == 0 or len == 0) return InvalidUriError.InvalidHostError;
                    parts += 1;
                    len = 0;
                },
                ':', '/', '?', '#' => {
                    if (out.host_type == .ipv6) return InvalidUriError.InvalidHostError; // must end with ]
                    if (i == 0 or len == 0) return InvalidUriError.InvalidHostError;
                    if (parts != 3) return InvalidUriError.InvalidHostError;
                    out.host = rest[0..i];
                    rest = rest[i..];
                    continue :parser .host_end;
                },
                ']', '%' => {
                    if (out.host_type == .ipv4) return InvalidUriError.InvalidHostError; // only valid when ipv4 is a l32 of ipv6
                    if (i == 0 or len == 0) return InvalidUriError.InvalidHostError;
                    if (parts != 3) return InvalidUriError.InvalidHostError;
                    out.host = rest_cache[0 .. i_cache + i];
                    rest = rest[i + 1 ..];
                    continue :parser if (c == ']') .host_end else .zone_id;
                },
                '0'...'9' => {
                    if (len > 3) return InvalidUriError.InvalidHostError; // too long

                    switch (len) {
                        0 => {}, // first digit, we ignore it for now
                        1 => if (rest[i - 1] == '0') return InvalidUriError.InvalidHostError, // leading zero
                        2 => switch (rest[i - 2]) {
                            '1' => {}, // 100 - 199
                            '2' => switch (rest[i - 1]) {
                                '0'...'4' => {}, // 200 - 249
                                '5' => if (c > '5') return InvalidUriError.InvalidHostError, // 250 - 255
                                else => return InvalidUriError.InvalidHostError,
                            },
                            else => return InvalidUriError.InvalidHostError,
                        },
                        else => unreachable,
                    }

                    len += 1;
                },
                else => return InvalidUriError.InvalidHostError,
            };

            if (parts != 3 or len == 0) return InvalidUriError.InvalidHostError;
            out.host = rest;
        },
        .host_regname => {
            var i: usize = 0;
            var in_userinfo = false;

            while (i < rest.len) : (i += 1) switch (rest[i]) {
                '@' => {
                    out.userinfo = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser .authority;
                },
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]);
                    i += 2;
                },
                '/', '?', '#' => {
                    out.host = rest[0..i];
                    rest = rest[i..];
                    continue :parser .host_end;
                },
                ':' => { // special case, we might be in a userinfo or start port
                    if (in_userinfo) continue;
                    if (std.mem.indexOfScalar(u8, @constCast(&std.mem.splitScalar(u8, rest, '/')).first(), '@') != null) {
                        in_userinfo = true;
                        continue;
                    }
                    out.host = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser .port;
                },
                else => switch (try classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim => return InvalidUriError.InvalidHostError,
                },
            };

            out.host = rest;
        },
        .host_end => {
            if (rest.len == 0) break :parser;
            switch (rest[0]) {
                '/' => continue :parser .path_start,
                ':' => {
                    rest = rest[1..];
                    continue :parser .port;
                },
                '?' => {
                    rest = rest[1..];
                    continue :parser .query;
                },
                '#' => {
                    rest = rest[1..];
                    continue :parser .fragment;
                },
                else => return InvalidUriError.InvalidHostError, // unexpected character after host
            }
        },
        .zone_id => {
            if (out.host_type != .ipv6) return InvalidUriError.InvalidHostError; // zone ID only valid for IPv6
            if (rest.len < 4) return InvalidUriError.InvalidHostError; // must be at least 4 characters (%25 + at least 1 pct-encoded / unreserved character)
            if (rest[0] != '%' or rest[1] != '2' or rest[2] != '5') return InvalidUriError.InvalidHostError; // must start with %25

            var i: usize = 3;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', '~' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]);
                    i += 2;
                },
                ']' => {
                    out.zone_id = rest[3..i];
                    rest = rest[i + 1 ..];
                    continue :parser .host_end;
                },
                else => return InvalidUriError.InvalidHostError, // invalid character in zone ID
            };
        },
        .port => {
            var port: u16 = 0;

            for (rest, 0..) |c, i| switch (c) {
                '0'...'9' => {
                    port = port * 10 + (c - '0');
                },
                '/' => {
                    out.port = port;
                    rest = rest[i..];
                    continue :parser .path_start;
                },
                '?' => {
                    out.port = port;
                    rest = rest[i + 1 ..];
                    continue :parser .query;
                },
                '#' => {
                    out.port = port;
                    rest = rest[i + 1 ..];
                    continue :parser .fragment;
                },
                else => return InvalidUriError.InvalidPortError, // invalid character in port
            };
        },
        .path_start => {
            if (out.kind == .relative_ref and rest.len > 0 and rest[0] != '/') continue :parser .path_noscheme;
            continue :parser .path; // path-abempty, path-absolute, path-empty, path-rootless
        },
        .path_noscheme => {
            for (rest) |c| switch (c) {
                ':' => return InvalidUriError.InvalidPathNoschemeError,
                '/', '?', '#' => break,
                else => {},
            };

            continue :parser .path;
        },
        .path => {
            var i: usize = 0;

            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':', '/', '@' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]);
                    i += 2;
                },
                '?', '#' => {
                    out.path = rest[0..i];
                    const c = rest[i];
                    rest = rest[i + 1 ..];
                    continue :parser if (c == '?') .query else .fragment;
                },
                else => switch (try classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim => return InvalidUriError.InvalidPathError,
                },
            };

            out.path = rest;
        },
        .query => {
            var i: usize = 0;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':', '/', '?', '@' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]);
                    i += 2;
                },
                '#' => {
                    out.query = rest[0..i];
                    rest = rest[i + 1 ..];
                    continue :parser .fragment;
                },
                else => switch (try classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim => return InvalidUriError.InvalidQueryError,
                },
            };
            out.query = rest;
        },
        .fragment => {
            var i: usize = 0;
            while (i < rest.len) : (i += 1) switch (rest[i]) {
                ':', '/', '?', '@', '#' => {},
                '%' => {
                    try validatePctEncoding(rest[i + 1 ..]);
                    i += 2;
                },
                else => switch (try classify(rest[i])) {
                    .unreserved, .sub_delim => {},
                    .gen_delim => return InvalidUriError.InvalidQueryError,
                },
            };
            out.fragment = rest;
        },
    }

    return out;
}

// INTERNAL

const ParsingState = enum {
    scheme,
    authority_start,
    authority,
    host_ipvfuture,
    host_ipv6,
    host_ipv4,
    host_regname,
    host_end,
    zone_id,
    port,
    path_start,
    path_noscheme,
    path,
    query,
    fragment,
};

const CharType = enum {
    unreserved,
    sub_delim,
    gen_delim,
};

fn classify(c: u8) InvalidUriError!CharType {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '.', '-', '_', '~' => .unreserved,
        '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' => .sub_delim,
        ':', '/', '?', '#', '[', ']', '@' => .gen_delim,
        else => InvalidUriError.InvalidCharacterError,
    };
}

fn validatePctEncoding(s: []const u8) InvalidUriError!void {
    if (s.len < 2 or !std.ascii.isHex(s[0]) or !std.ascii.isHex(s[1])) return InvalidUriError.InvalidCharacterError;
}

// TESTS

const uri_entries = [_]struct { in: []const u8, out: UriRef }{
    .{ // URI, authority, path-empty
        .in = "http://example.com",
        .out = UriRef{
            .kind = .uri,
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "",
        },
    },
    .{ // URI, authority, path-absolute
        .in = "http://example.com/path/to/resource",
        .out = UriRef{
            .kind = .uri,
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
        },
    },
    .{ // path with percent-encoding
        .in = "http://example.com/path/to/resource%20with%20spaces",
        .out = UriRef{
            .kind = .uri,
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource%20with%20spaces",
        },
    },
    .{ // fragment with percent-encoding
        .in = "http://example.com/path#fragment%20with%20spaces",
        .out = UriRef{
            .kind = .uri,
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
            .kind = .uri,
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
            .kind = .uri,
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
            .kind = .uri,
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
            .kind = .uri,
            .scheme = "http",
            .host = "example.com",
            .host_type = .domain,
            .path = "/path",
            .query = "query%20with%20spaces",
        },
    },
    .{ // no authority, path-rootless
        .in = "mailto:john.doe@example.com",
        .out = UriRef{
            .kind = .uri,
            .scheme = "mailto",
            .path = "john.doe@example.com",
        },
    },
    .{ // no authority, path-absolute
        .in = "file:///path/to/file.txt",
        .out = UriRef{
            .kind = .uri,
            .scheme = "file",
            .host = "",
            .host_type = .domain,
            .path = "/path/to/file.txt",
        },
    },
    .{ // no authority, path-empty
        .in = "http:",
        .out = UriRef{
            .kind = .uri,
            .scheme = "http",
        },
    },
    .{ // unescaped :// in query should not create a scheme
        .in = "http://example.com/path?from=http://example.com",
        .out = UriRef{
            .kind = .uri,
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
            .kind = .relative_ref,
            .host = "example.com",
            .host_type = .domain,
            .path = "/path/to/resource",
        },
    },
    .{ // leading // without scheme, with userinfo, path, and query
        .in = "//user@example.com/path/to/resource?query=value",
        .out = UriRef{
            .kind = .relative_ref,
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
            .kind = .uri,
            .scheme = "http",
            .host = "192.168.0.1",
            .host_type = .ipv4,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv4 and port in authority
        .in = "http://192.168.0.1:8080/path/to/resource",
        .out = UriRef{
            .kind = .uri,
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
            .kind = .uri,
            .scheme = "http",
            .host = "2001:db8::1",
            .host_type = .ipv6,
            .path = "/path/to/resource",
        },
    },
    .{ // IPv6 address with zone ID in authority
        .in = "http://[2001:db8::1%25eth0]/path/to/resource",
        .out = UriRef{
            .kind = .uri,
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
            .kind = .uri,
            .scheme = "http",
            .host = "2001:db8::192.168.0.1",
            .host_type = .ipv6,
            .path = "/path/to/resource",
        },
    },
};

comptime {
    // URI parsing
    for (uri_entries) |entry| {
        _ = struct {
            test {
                const parsed = try parse(entry.in);

                try std.testing.expectEqual(entry.out.kind, parsed.kind);

                if (entry.out.kind == .uri) {
                    try std.testing.expect(parsed.scheme != null);
                    try std.testing.expectEqualStrings(entry.out.scheme.?, parsed.scheme.?);
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
