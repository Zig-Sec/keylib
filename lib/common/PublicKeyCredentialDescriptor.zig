//! Contains the attributes that are specified by a caller when referring to a
//! public key credential. See WebAuthn §5.8.3.

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../main.zig");
const dt = @import("data_types.zig");

const AuthenticatorTransports = fido.common.AuthenticatorTransports;
const PublicKeyCredentialType = fido.common.PublicKeyCredentialType;

/// The credential id
id: dt.ABS128B,
/// Type of the credential
type: PublicKeyCredentialType,
/// Transport methods
transports: ?dt.ABSAuthenticatorTransports = null,

pub fn new(
    id: []const u8,
    t: PublicKeyCredentialType,
    transports: ?[]const AuthenticatorTransports,
) !@This() {
    return .{
        .id = (try dt.ABS128B.fromSlice(id)).?,
        .type = t,
        .transports = try dt.ABSAuthenticatorTransports.fromSlice(transports),
    };
}

test "PublicKeyCredentialDescriptor test #1" {
    const allocator = std.testing.allocator;
    var str = std.Io.Writer.Allocating.init(allocator);
    defer str.deinit();

    const d = try new("\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51", .@"public-key", null);

    try @import("zbor").stringify(d, .{}, &str.writer);
    try std.testing.expectEqualSlices(u8, "\xa2\x62\x69\x64\x58\x40\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79", str.written());
}

test "PublicKeyCredentialDescriptor test #2" {
    const descriptor = try new("\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51", .@"public-key", &.{ .usb, .internal });
    const expected = "\xa3\x62\x69\x64\x58\x40\x5c\x7b\xc6\x57\x09\xed\xcd\xbc\x8a\x61\x2f\x1f\x5e\x97\xd0\x15\xbd\x0e\xc7\x33\x28\x0b\x5c\xb5\x78\x62\x6d\xba\x37\xa1\xe5\x10\xc3\x9e\x79\xf8\x20\x0e\x95\xf7\x9d\x50\x5c\x44\x35\x61\xac\x07\x1e\xa7\x14\x3a\xd0\x6e\xf4\x8b\x56\xdd\x5d\x71\x22\x79\x77\x51\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x6a\x74\x72\x61\x6e\x73\x70\x6f\x72\x74\x73\x82\x63\x75\x73\x62\x68\x69\x6e\x74\x65\x72\x6e\x61\x6c";

    var arr = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer arr.deinit();

    try cbor.stringify(descriptor, .{}, &arr.writer);

    try std.testing.expectEqualSlices(u8, expected, arr.written());

    const di = try cbor.DataItem.new(expected);
    const descriptor2 = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqualStrings(descriptor.id.get(), descriptor2.id.get());
    try std.testing.expectEqual(descriptor.type, descriptor2.type);
    try std.testing.expectEqualSlices(AuthenticatorTransports, descriptor.transports.?.get(), descriptor2.transports.?.get());
}
