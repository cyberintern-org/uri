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
    scheme: ?[]const u8 = null,
    userinfo: ?[]const u8 = null,
    host: ?[]const u8 = null,
    host_type: ?HostType = null,
    port: ?u16 = null,
    path: []const u8 = "",
    raw_query: ?[]const u8 = null,
    raw_fragment: ?[]const u8 = null,

    kind: Kind = .indeterminate,
};

/// Parser implementation according to [RFC 3986, Chapter 3. Syntax Components](https://datatracker.ietf.org/doc/html/rfc3986#autoid-17).
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
///     - IP-literal = "[" ( IPv6address / IPvFuture ) "]"
///       - IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
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
    rest, out.raw_fragment = splitFirstEnd(rest, '#');
    rest, out.raw_query = splitFirstEnd(rest, '?');

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

        out.userinfo, out.host, out.host_type, out.port = try parseAuthority(authority);
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

fn parseAuthority(s: []const u8) InvalidUriError!struct { ?[]const u8, []const u8, ?HostType, ?u16 } {
    const userinfo, var host = splitFirstStart(s, '@');
    var host_type: ?HostType = null;
    var port_string: ?[]const u8 = null;

    if (std.mem.startsWith(u8, host, "[")) { // IP-literal
        const temp = host[1..];
        host, port_string = splitLastEnd(host[1..], ']');
        if (port_string) |p| {
            if (p[0] == ':') port_string = p[1..] else return InvalidUriError.InvalidHostError; // no colon
        }

        if (host.len == 0 or host.len == temp.len) return InvalidUriError.InvalidHostError; // empty or no closing bracket
        if (try parseIPvFuture(host)) {
            host_type = HostType.ipvfuture;
        } else if (try parseIPv6(host)) {
            host_type = HostType.ipv6;
        } else {
            return InvalidUriError.InvalidHostError;
        }
    } else { // IPv4address or reg-name
        host, port_string = splitLastEnd(host, ':');
        if (try parseIPv4(host)) {
            host_type = HostType.ipv4;
        } else {
            try parseRegName(host);
            host_type = HostType.domain;
        }
    }

    if (port_string) |p| {
        const port = std.fmt.parseInt(u16, p, 10) catch return InvalidUriError.InvalidPortError;
        return .{ userinfo, host, host_type, port };
    }

    return .{ userinfo, host, host_type, null };
}

fn parseIPvFuture(s: []const u8) InvalidUriError!bool {
    var found_dot = false;
    var found_second = false;
    l: for (s, 0..) |c, i| switch (i) {
        0 => if (c != 'v') return false,
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
    return true;
}

fn parseIPv6(s: []const u8) InvalidUriError!bool {
    _ = s;
    return true; // TODO: Implement IPv6 parsing
}

fn parseIPv4(s: []const u8) InvalidUriError!bool {
    var parts = std.mem.splitScalar(u8, s, '.');
    var len: usize = 0;

    while (parts.next()) |part| : (len += 1) switch (part.len) {
        0 => return false, // empty part
        1 => if (!std.ascii.isDigit(part[0])) return false, // 0-9
        2 => { // 10-99
            if (part[0] < '1' or part[0] > '9') return false;
            if (!std.ascii.isDigit(part[1])) return false;
        },
        3 => switch (part[0]) {
            '1' => if (!std.ascii.isDigit(part[1]) or !std.ascii.isDigit(part[2])) return false, // 100-199
            '2' => switch (part[1]) {
                '0'...'4' => if (!std.ascii.isDigit(part[2])) return false, // 200-249
                '5' => if (part[2] < '0' or part[2] > '5') return false, // 250-255
                else => return false, // invalid second digit
            },
            else => return false,
        },
        else => return false, // too long part
    };

    return len == 4;
}

fn parseRegName(s: []const u8) InvalidUriError!void {
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

fn splitLastEnd(s: []const u8, delimiter: u8) struct { []const u8, ?[]const u8 } {
    const idx = std.mem.lastIndexOfScalar(u8, s, delimiter);

    if (idx == null) return .{ s, null };
    if (idx.? == 0) return .{ "", s[1..] };
    if (idx.? == s.len - 1) return .{ s[0..idx.?], null };
    return .{ s[0..idx.?], s[idx.? + 1 ..] };
}

// TESTS

const uri_entries = [_]struct { in: []const u8, out: UriRef }{
    .{
        .in = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#top",
        .out = UriRef{
            .scheme = "https",
            .userinfo = "john.doe",
            .host = "www.example.com",
            .host_type = .domain,
            .port = 1234,
            .path = "/forum/questions/",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = "top",
        },
    },
    .{
        .in = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#:~:text=whatever",
        .out = UriRef{
            .scheme = "https",
            .userinfo = "john.doe",
            .host = "www.example.com",
            .host_type = .domain,
            .port = 1234,
            .path = "/forum/questions/",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = ":~:text=whatever",
        },
    },
    .{
        .in = "ldap://[2001:db8::7]/c=GB?objectClass?one",
        .out = UriRef{
            .scheme = "ldap",
            .host = "2001:db8::7",
            .host_type = .ipv6,
            .path = "/c=GB",
            .raw_query = "objectClass?one",
        },
    },
    .{
        .in = "mailto:John.Doe@example.com",
        .out = UriRef{
            .scheme = "mailto",
            .path = "John.Doe@example.com",
        },
    },
    .{
        .in = "news:comp.infosystems.www.servers.unix",
        .out = UriRef{
            .scheme = "news",
            .path = "comp.infosystems.www.servers.unix",
        },
    },
    .{
        .in = "tel:+1-816-555-1212",
        .out = UriRef{
            .scheme = "tel",
            .path = "+1-816-555-1212",
        },
    },
    .{
        .in = "telnet://192.0.2.16:80/",
        .out = UriRef{
            .scheme = "telnet",
            .host = "192.0.2.16",
            .host_type = .ipv4,
            .port = 80,
            .path = "/",
        },
    },
    .{
        .in = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        .out = UriRef{
            .scheme = "urn",
            .path = "oasis:names:specification:docbook:dtd:xml:4.1.2",
        },
    },
    .{
        .in = "file:///etc/passwd",
        .out = UriRef{
            .scheme = "file",
            .host = "",
            .host_type = .domain,
            .path = "/etc/passwd",
        },
    },
};

comptime {
    // URI parsing
    for (uri_entries) |entry| {
        _ = struct {
            test {
                const parsed = try parse(entry.in);

                try std.testing.expectEqual(Kind.uri, parsed.kind);
                try std.testing.expectEqualStrings(entry.out.scheme.?, parsed.scheme.?);
                try std.testing.expectEqualStrings(entry.out.userinfo orelse "", parsed.userinfo orelse "");

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

                try std.testing.expectEqual(entry.out.port, parsed.port);
                try std.testing.expectEqualStrings(entry.out.path, parsed.path);
                try std.testing.expectEqualStrings(entry.out.raw_query orelse "", parsed.raw_query orelse "");
                try std.testing.expectEqualStrings(entry.out.raw_fragment orelse "", parsed.raw_fragment orelse "");
            }
        };
    }
}
