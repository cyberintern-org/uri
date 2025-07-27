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
const parsing = @import("parsing.zig");

// API

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
    raw: []const u8 = "",

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

/// Error type for URI parsing errors.
pub const InvalidUriError = parsing.InvalidUriError;

/// Parser implementation according to [RFC 3986, Chapter 3. Syntax Components](https://datatracker.ietf.org/doc/html/rfc3986#autoid-17)
/// and [RFC 6874, Chapter 2. Specification](https://datatracker.ietf.org/doc/html/rfc6874).
///
/// (Approximately) single-pass and without dynamic memory allocation.
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
pub const parse = parsing.parse;

// TESTS

test {
    std.testing.refAllDeclsRecursive(@This());
}
