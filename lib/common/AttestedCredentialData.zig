//! Attested credential data is a variable-length byte array added to the
//! authenticator data when generating an attestation object for a given credential

const std = @import("std");
const cbor = @import("zbor");
const dt = @import("data_types.zig");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The AAGUID of the authenticator
aaguid: [16]u8,
/// Byte length L of Credential ID, 16-bit unsigned big-endian integer
credential_length: u16,
/// Credential ID
credential_id: dt.ABS64B,
/// The credential public key encoded in COSE_Key format
credential_public_key: dt.ABS256B,

/// Encode the given AttestedCredentialData for usage with the AuthenticatorData struct
pub fn encode(self: *const @This(), out: *std.Io.Writer) !void {
    try out.writeAll(self.aaguid[0..]);
    // length is encoded in big-endian format
    try out.writeByte(@as(u8, @intCast(self.credential_length >> 8)));
    try out.writeByte(@as(u8, @intCast(self.credential_length & 0xff)));
    try out.writeAll(self.credential_id.get());
    try out.writeAll(self.credential_public_key.get());
}

pub fn new(
    aaguid: [16]u8,
    credential_id: []const u8,
    credential_public_key: []const u8,
) !@This() {
    return .{
        .aaguid = aaguid,
        .credential_length = @as(u16, @intCast(credential_id.len)),
        .credential_id = (try dt.ABS64B.fromSlice(credential_id)).?,
        .credential_public_key = (try dt.ABS256B.fromSlice(credential_public_key)).?,
    };
}

test "attestation credential data" {
    const allocator = std.testing.allocator;
    var a = std.Io.Writer.Allocating.init(allocator);
    defer a.deinit();

    const k = try cbor.cose.Key.fromP256Pub(.Es256, try EcdsaP256Sha256.PublicKey.fromSec1("\x04\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52"), allocator);
    defer k.deinit(allocator);
    var serialized_cred = std.Io.Writer.Allocating.init(allocator);
    defer serialized_cred.deinit();
    try cbor.stringify(&k, .{ .enum_serialization_type = .Integer }, &serialized_cred.writer);

    const acd = try new(
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        &.{ 0xb3, 0xf8, 0xcd, 0xb1, 0x80, 0x20, 0x91, 0x76, 0xfa, 0x20, 0x1a, 0x51, 0x6d, 0x1b, 0x42, 0xf8, 0x02, 0xa8, 0x0d, 0xaf, 0x48, 0xd0, 0x37, 0x88, 0x21, 0xa6, 0xfb, 0xdd, 0x52, 0xde, 0x16, 0xb7, 0xef, 0xf6, 0x22, 0x25, 0x72, 0x43, 0x8d, 0xe5, 0x85, 0x7e, 0x70, 0xf9, 0xef, 0x05, 0x80, 0xe9, 0x37, 0xe3, 0x00, 0xae, 0xd0, 0xdf, 0xf1, 0x3f, 0xb6, 0xa3, 0x3e, 0xc3, 0x8b, 0x81, 0xca, 0xd0 },
        serialized_cred.written(),
    );

    const w = &a.writer;
    try acd.encode(w);

    try std.testing.expectEqualSlices(u8, a.written(), "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\xb3\xf8\xcd\xb1\x80\x20\x91\x76\xfa\x20\x1a\x51\x6d\x1b\x42\xf8\x02\xa8\x0d\xaf\x48\xd0\x37\x88\x21\xa6\xfb\xdd\x52\xde\x16\xb7\xef\xf6\x22\x25\x72\x43\x8d\xe5\x85\x7e\x70\xf9\xef\x05\x80\xe9\x37\xe3\x00\xae\xd0\xdf\xf1\x3f\xb6\xa3\x3e\xc3\x8b\x81\xca\xd0\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\x22\x58\x20\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52");
}
