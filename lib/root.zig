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

//! URI parsing, production and normalization implementation according to [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986).

const std = @import("std");

// API

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
    InvalidPathNoschemeError,
    InvalidHostError,
    InvalidPortError,
};

pub const Kind = enum {
    indeterminate,
    uri,
    relative_ref,
};

pub const HostType = enum {
    domain,
    ipv4,
    ipv6,
    ipvfuture,
};

pub const UriRef = struct {
    kind: Kind = .indeterminate,
    scheme: ?[]const u8 = null,
    userinfo: ?[]const u8 = null,
    host: ?[]const u8 = null,
    host_type: ?HostType = null,
    zone_id: ?[]const u8 = null,
    port: ?u16 = null,
    path: []const u8 = "",
    query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,
};

/// Parser implementation according to [RFC 3986, Chapter 3. Syntax Components](https://datatracker.ietf.org/doc/html/rfc3986#autoid-17)
/// and updated by [RFC 6874, Chapter 2. Specification](https://datatracker.ietf.org/doc/html/rfc6874).
///
/// Basic syntax:
/// - URI-reference = URI | relative-ref
/// - URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
/// - relative-ref = relative-part [ "?" query ] [ "#" fragment ]
/// - hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
/// - relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
///
/// Syntax definitions:
/// - scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
/// - authority = [ userinfo "@" ] host [ ":" port ]
///   - userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
///   - host = IP-literal / IPv4address / reg-name
///     - IP-literal = "[" ( IPv6address / IPv6addrz / IPvFuture ) "]"
///       - IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
///       - IPv6addrz = IPv6address "%25" ZoneID
///        - ZoneID = 1*( unreserved / pct-encoded)
///       - IPv6address =                 6( h16 ":" ) ls32
///            /                     "::" 5( h16 ":" ) ls32
///            / [             h16 ] "::" 4( h16 ":" ) ls32
///            / [ *1(h16 ":") h16 ] "::" 3( h16 ":" ) ls32
///            / [ *2(h16 ":") h16 ] "::" 2( h16 ":" ) ls32
///            / [ *3(h16 ":") h16 ] "::"    h16 ":"   ls32
///            / [ *4(h16 ":") h16 ] "::"              ls32
///            / [ *5(h16 ":") h16 ] "::"              h16
///            / [ *6(h16 ":") h16 ] "::"
///         - ls32 = ( h16 ":" h16 ) / IPv4address
///         - h16 = 1*HEXDIG
///     - IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
///       - dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
///     - reg-name = *( unreserved / pct-encoded / sub-delims )
///   - port = *DIGIT
/// - path = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty
///   - path-abempty = *( "/" segment )
///   - path-absolute = "/" [ segment-nz *( "/" segment ) ]
///   - path-rootless = segment-nz *( "/" segment )
///   - path-noscheme = segment-nz-nc *( "/" segment )
///   - path-empty = 0pchar
///     - segment = *pchar
///     - segment-nz = 1*pchar
///     - segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
///     - pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
/// - query = *( pchar / "/" / "?" )
/// - fragment = *( pchar / "/" / "?" )
///
/// Character definitions:
/// - pct-encoded = "%" HEXDIG HEXDIG
/// - unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// - reserved = gen-delims / sub-delims
///   - gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"
///   - sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="
pub fn parse(s: []const u8) InvalidUriError!UriRef {
    if (s.len == 0) return InvalidUriError.EmptyUriError;
    if (std.mem.indexOfAny(u8, s, &.{ ' ', 0x7f })) |_| return InvalidUriError.InvalidCharacterError;

    var out = UriRef{};
    var rest = s;

    out.scheme, rest = try parseScheme(rest);
    out.kind = if (out.scheme != null) .uri else .relative_ref;
    rest, out.fragment = splitFirstEnd(rest, '#');
    rest, out.query = splitFirstEnd(rest, '?');

    // path-absolute, path-rootless, path-empty don't require additional handling
    if (rest.len != 0 and rest[0] != '/' and out.kind == .relative_ref) { // path-noscheme
        var p = std.mem.splitScalar(u8, rest, '/');
        if (std.mem.indexOfScalar(u8, p.first(), ':')) |_| {
            return InvalidUriError.InvalidPathNoschemeError;
        }
    } else if (std.mem.startsWith(u8, rest, "//")) { // authority path-abempty
        var authority = rest[2..];
        rest = "";

        if (std.mem.indexOfScalar(u8, authority, '/')) |sl| {
            rest = authority[sl..];
            authority = authority[0..sl];
        }

        out.userinfo, out.host, out.host_type, out.zone_id, out.port = try parseAuthority(authority);
    }

    out.path = rest;
    return out;
}

// INTERNAL

const gen_delims = [_]u8{ ':', '/', '?', '#', '[', ']', '@' };
const sub_delims = [_]u8{ '!', '$', '&', '\'', '(', ')', '*', '+', ',', ';', '=' };
const unreserved_no_alphanumeric = [_]u8{ '-', '.', '_', '~' };

fn parseScheme(s: []const u8) InvalidUriError!struct { ?[]const u8, []const u8 } {
    l: for (s, 0..) |c, i| switch (c) {
        'A'...'Z', 'a'...'z' => {},
        '0'...'9', '+', '-', '.' => if (i == 0) break :l,
        ':' => return if (i == 0) InvalidUriError.EmptySchemeError else .{ s[0..i], s[i + 1 ..] },
        else => break :l,
    };

    return .{ null, s };
}

fn parseAuthority(s: []const u8) InvalidUriError!struct { ?[]const u8, []const u8, ?HostType, ?[]const u8, ?u16 } {
    const userinfo, var host = splitLastStart(s, '@');
    var host_type: ?HostType = null;
    var port_string: ?[]const u8 = null;
    var zone_id: ?[]const u8 = null;

    if (std.mem.startsWith(u8, host, "[")) { // IP-literal
        const temp = host[1..];
        host, port_string = splitLastEnd(host[1..], ']');
        if (port_string) |p| {
            if (p[0] == ':') port_string = p[1..] else return InvalidUriError.InvalidHostError; // no colon
        }

        if (host.len == 0 or host.len == temp.len) return InvalidUriError.InvalidHostError; // empty or no closing bracket
        if (try parseIPvFuture(host)) |h| {
            host = h;
            host_type = HostType.ipvfuture;
        } else {
            host, zone_id = splitFirstEnd(host, '%');
            if (zone_id) |z| {
                if (z.len < 4 or std.mem.eql(u8, z[0..3], "%25")) return InvalidUriError.InvalidHostError;
                for (z[3..]) |c| {
                    if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, &unreserved_no_alphanumeric, c) == null and c != '%') {
                        return InvalidUriError.InvalidHostError; // invalid character in zone ID
                    }
                }
                zone_id = z[3..];
            }
            if (try parseIPv6(host)) |h| {
                host = h;
                host_type = HostType.ipv6;
            } else {
                return InvalidUriError.InvalidHostError; // invalid IPv6 address
            }
        }
    } else { // IPv4address or reg-name
        host, port_string = splitLastEnd(host, ':');
        if (try parseIPv4(host)) |h| {
            host = h;
            host_type = HostType.ipv4;
        } else {
            host = try parseRegName(host);
            host_type = HostType.domain;
        }
    }

    if (port_string) |p| {
        const port = std.fmt.parseInt(u16, p, 10) catch return InvalidUriError.InvalidPortError;
        return .{ userinfo, host, host_type, zone_id, port };
    }

    return .{ userinfo, host, host_type, zone_id, null };
}

fn parseIPvFuture(s: []const u8) InvalidUriError!?[]const u8 {
    var found_dot = false;
    var found_second = false;
    l: for (s, 0..) |c, i| switch (i) {
        0 => if (c != 'v') return null,
        1 => switch (c) {
            '.' => found_dot = true,
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return InvalidUriError.InvalidHostError,
        },
        2, 3 => {
            if (!found_dot and c != '.') return InvalidUriError.InvalidHostError;
            if (c == '.') {
                found_dot = true;
                continue :l;
            }

            if (i == 3 and found_second) return InvalidUriError.InvalidHostError; // can have at most 1 character after the dot

            if (std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, &unreserved_no_alphanumeric, c) != null) {
                found_second = true;
                continue :l;
            }
            if (std.mem.indexOfScalar(u8, &sub_delims, c)) |_| {
                found_second = true;
                continue :l;
            }
            if (c == ':') {
                found_second = true;
                continue :l;
            }

            return InvalidUriError.InvalidHostError; // invalid character
        },
        else => return InvalidUriError.InvalidHostError, // more than 1 character after the dot
    };

    if (!found_dot) return InvalidUriError.InvalidHostError; // must have at least one dot
    return s;
}

fn parseIPv6(s: []const u8) InvalidUriError!?[]const u8 {
    var parts = std.mem.splitSequence(u8, s, "::");
    var left = parts.next();
    var right = parts.next();

    if (right == null) { // only right -> 6(h16 ":") ls32
        right = left;
        left = null;
    }

    var left_parts_count: i32 = if (left == null) -1 else 0;

    if (left != null and left.?.len > 0) {
        var left_parts = std.mem.splitScalar(u8, left orelse "", ':');

        while (left_parts.next()) |part| : (left_parts_count += 1) {
            if (try parseh16(part) == null) return InvalidUriError.InvalidHostError; // h16 must be 1-4 hex digits
        }

        if (left_parts_count > 7) return InvalidUriError.InvalidHostError; // too many parts
        if (right.?.len == 0) return s; // *6(h16 ":") h16 "::"
    }

    var rest: ?[]const u8, var ls32 = splitLastEnd(right.?, ':');

    if (ls32 == null) { // ... "::" ls32 / ... "::" h16
        ls32 = rest;
        rest = null;
    }

    if (try parsels32(ls32.?) == null) return InvalidUriError.InvalidHostError; // ls32 must be IPv4address or h16

    if (rest) |r| {
        var rest_parts = std.mem.splitScalar(u8, r, ':');
        var rest_parts_count: usize = 0;
        while (rest_parts.next()) |part| : (rest_parts_count += 1) {
            if (try parseh16(part) == null) return InvalidUriError.InvalidHostError; // h16 must be 1-4 hex digits
        }

        if (rest_parts_count > (6 - @min(6, left_parts_count))) return InvalidUriError.InvalidHostError; // too many parts
    }

    return s;
}

fn parseIPv4(s: []const u8) InvalidUriError!?[]const u8 {
    var parts = std.mem.splitScalar(u8, s, '.');
    var len: usize = 0;

    while (parts.next()) |part| : (len += 1) switch (part.len) {
        0 => return null, // empty part
        1 => if (!std.ascii.isDigit(part[0])) return null, // 0-9
        2 => { // 10-99
            if (part[0] < '1' or part[0] > '9') return null;
            if (!std.ascii.isDigit(part[1])) return null;
        },
        3 => switch (part[0]) {
            '1' => if (!std.ascii.isDigit(part[1]) or !std.ascii.isDigit(part[2])) return null, // 100-199
            '2' => switch (part[1]) {
                '0'...'4' => if (!std.ascii.isDigit(part[2])) return null, // 200-249
                '5' => if (part[2] < '0' or part[2] > '5') return null, // 250-255
                else => return null, // invalid second digit
            },
            else => return null,
        },
        else => return null, // too long part
    };

    return if (len == 4) s else null; // must have exactly 4 parts
}

fn parseRegName(s: []const u8) InvalidUriError![]const u8 {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, &unreserved_no_alphanumeric, c) != null) continue;
        if (std.mem.indexOfScalar(u8, &sub_delims, c)) |_| continue;
        if (c == '%') {
            if (i + 2 >= s.len) return InvalidUriError.InvalidHostError; // not enough characters for pct-encoded
            if (!std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) {
                return InvalidUriError.InvalidHostError; // invalid pct-encoded character
            }
            i += 1; // skip the next two characters
            continue;
        }

        return InvalidUriError.InvalidHostError; // invalid character
    }
    return s;
}

fn parseh16(s: []const u8) InvalidUriError!?[]const u8 {
    if (s.len == 0 or s.len > 4) return null; // h16 must be 1-4 hex digits
    for (s) |c| if (!std.ascii.isHex(c)) return null;
    return s;
}

fn parsels32(s: []const u8) InvalidUriError!?[]const u8 {
    return if (try parseIPv4(s)) |ip| ip else try parseh16(s);
}

fn splitFirstStart(s: []const u8, delimiter: u8) struct { ?[]const u8, []const u8 } {
    const i = std.mem.indexOfScalar(u8, s, delimiter);

    if (i == null) return .{ null, s };
    if (i.? == 0) return .{ "", s[1..] };
    if (i.? == s.len - 1) return .{ s[0..i.?], "" };
    return .{ s[0..i.?], s[i.? + 1 ..] };
}

fn splitFirstEnd(s: []const u8, delimiter: u8) struct { []const u8, ?[]const u8 } {
    var iter = std.mem.splitScalar(u8, s, delimiter);
    const first, const rest = .{ iter.first(), iter.rest() };
    return if (rest.len == 0) .{ first, null } else .{ first, rest };
}

fn splitLastStart(s: []const u8, delimiter: u8) struct { ?[]const u8, []const u8 } {
    const idx = std.mem.lastIndexOfScalar(u8, s, delimiter);
    if (idx == null) return .{ null, s };
    if (idx.? == 0) return .{ "", s[1..] };
    if (idx.? == s.len - 1) return .{ s[0..idx.?], "" };
    return .{ s[0..idx.?], s[idx.? + 1 ..] };
}

fn splitLastEnd(s: []const u8, delimiter: u8) struct { []const u8, ?[]const u8 } {
    const idx = std.mem.lastIndexOfScalar(u8, s, delimiter);

    if (idx == null) return .{ s, null };
    if (idx.? == 0) return .{ "", s[1..] };
    if (idx.? == s.len - 1) return .{ s[0..idx.?], null };
    return .{ s[0..idx.?], s[idx.? + 1 ..] };
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

                if (entry.out.host) |host| {
                    try std.testing.expect(parsed.host != null);
                    try std.testing.expectEqualStrings(host, parsed.host.?);
                } else {
                    try std.testing.expectEqual(null, parsed.host);
                }

                if (entry.out.host_type) |host_type| {
                    try std.testing.expect(parsed.host_type != null);
                    try std.testing.expectEqual(host_type, parsed.host_type.?);
                } else {
                    try std.testing.expectEqual(null, parsed.host_type);
                }

                if (entry.out.zone_id) |zone_id| {
                    try std.testing.expect(parsed.zone_id != null);
                    try std.testing.expectEqualStrings(zone_id, parsed.zone_id.?);
                } else {
                    try std.testing.expectEqual(null, parsed.zone_id);
                }

                try std.testing.expectEqual(entry.out.port, parsed.port);
                try std.testing.expectEqualStrings(entry.out.path, parsed.path);
            }
        };
    }
}
