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

pub const parsing = @import("parsing.zig");

test {
    std.testing.refAllDecls(@This());
}
