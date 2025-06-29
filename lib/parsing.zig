// liburi - URI parsing implementation for the www cyberintern work
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

//! Parser implementation according to [RFC 3986, Chapter 3. Syntax Components](https://datatracker.ietf.org/doc/html/rfc3986#autoid-17).
//!
//! Basic syntax:
//! URI-reference = URI | relative-ref
//! URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
//! relative-ref = relative-part [ "?" query ] [ "#" fragment ]
//! hier-part = "//" authority path-abempty / path-absolute / path-rootless / path-empty
//! relative-part = "//" authority path-abempty / path-absolute / path-noscheme / path-empty
//!
//! Syntax definitions:
//! - scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//! - authority = [ userinfo "@" ] host [ ":" port ]
//!   - userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
//!   - host = IP-literal / IPv4address / reg-name
//!     - IP-literal = "[" ( IPv6address / IPvFuture ) "]"
//!       - IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
//!       - IPv6address =                 6( h16 ":" ) ls32
//!            /                     "::" 5( h16 ":" ) ls32
//!            / [             h16 ] "::" 4( h16 ":" ) ls32
//!            / [ *1(h16 ":") h16 ] "::" 3( h16 ":" ) ls32
//!            / [ *2(h16 ":") h16 ] "::" 2( h16 ":" ) ls32
//!            / [ *3(h16 ":") h16 ] "::"    h16 ":"   ls32
//!            / [ *4(h16 ":") h16 ] "::"              ls32
//!            / [ *5(h16 ":") h16 ] "::"              h16
//!            / [ *6(h16 ":") h16 ] "::"
//!         - ls32 = ( h16 ":" h16 ) / IPv4address
//!         - h16 = 1*HEXDIG
//!     - IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
//!       - dec-octet = DIGIT / %x31-39 DIGIT / "1" 2DIGIT / "2" %x30-34 DIGIT / "25" %x30-35
//!     - reg-name = *( unreserved / pct-encoded / sub-delims )
//!   - port = *DIGIT
//! - path = path-abempty / path-absolute / path-noscheme / path-rootless / path-empty
//!   - path-abempty = *( "/" segment )
//!   - path-absolute = "/" [ segment-nz *( "/" segment ) ]
//!   - path-rootless = segment-nz *( "/" segment )
//!   - path-noscheme = segment-nz-nc *( "/" segment )
//!   - path-empty = 0pchar
//!     - segment = *pchar
//!     - segment-nz = 1*pchar
//!     - segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//!     - pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
//! - query = *( pchar / "/" / "?" )
//! - fragment = *( pchar / "/" / "?" )
//!
//! Character definitions:
//! pct-encoded = "%" HEXDIG HEXDIG
//! unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
//! reserved = gen-delims / sub-delims
//! gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"
//! sub-delims = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="

const std = @import("std");
const uri = @import("root.zig");

// API

pub const InvalidUriError = error{
    InvalidCharacterError,
    EmptyUriError,
    EmptySchemeError,
    EmptyAuthorityError,
};

/// Parses a URI or a relative reference from a string slice, returning an error if the string is not a valid URI reference.
pub fn parse(s: []const u8) InvalidUriError!uri.UriRef {
    if (s.len == 0) return InvalidUriError.EmptyUriError;
    if (std.mem.indexOfAny(u8, s, &.{ ' ', 0x7f })) |_| return InvalidUriError.InvalidCharacterError;

    var out = uri.UriRef{};
    var rest = s;

    out.scheme, rest = try parseScheme(rest);
    out.kind = if (out.scheme != null) uri.Kind.uri else uri.Kind.relative_ref;
    rest, out.raw_fragment = splitEnd(rest, '#');
    rest, out.raw_query = splitEnd(rest, '?');

    return out;
}

// INTERNAL

fn parseScheme(s: []const u8) InvalidUriError!struct { ?[]const u8, []const u8 } {
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

const uri_entries = [_]struct { raw: []const u8, parsed: uri.UriRef }{
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#top",
        .parsed = uri.UriRef{
            .scheme = "https",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = "top",
        },
    },
    .{
        .raw = "https://john.doe@www.example.com:1234/forum/questions/?tag=networking&order=newest#:~:text=whatever",
        .parsed = uri.UriRef{
            .scheme = "https",
            .raw_query = "tag=networking&order=newest",
            .raw_fragment = ":~:text=whatever",
        },
    },
    .{
        .raw = "ldap://[2001:db8::7]/c=GB?objectClass?one",
        .parsed = uri.UriRef{
            .scheme = "ldap",
            .raw_query = "objectClass?one",
        },
    },
    .{
        .raw = "mailto:John.Doe@example.com",
        .parsed = uri.UriRef{
            .scheme = "mailto",
        },
    },
    .{
        .raw = "news:comp.infosystems.www.servers.unix",
        .parsed = uri.UriRef{
            .scheme = "news",
        },
    },
    .{
        .raw = "tel:+1-816-555-1212",
        .parsed = uri.UriRef{
            .scheme = "tel",
        },
    },
    .{
        .raw = "telnet://192.0.2.16:80/",
        .parsed = uri.UriRef{
            .scheme = "telnet",
        },
    },
    .{
        .raw = "urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
        .parsed = uri.UriRef{
            .scheme = "urn",
        },
    },
    .{
        .raw = "file:///etc/passwd",
        .parsed = uri.UriRef{
            .scheme = "file",
        },
    },
};

test "URI parsing" {
    for (uri_entries) |entry| {
        const parsed = try parse(entry.raw);

        try std.testing.expectEqual(uri.Kind.uri, parsed.kind);
        try std.testing.expectEqualStrings(entry.parsed.scheme.?, parsed.scheme.?);
        try std.testing.expectEqualStrings(entry.parsed.raw_query orelse "", parsed.raw_query orelse "");
        try std.testing.expectEqualStrings(entry.parsed.raw_fragment orelse "", parsed.raw_fragment orelse "");
    }
}
