const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");
const dt = fido.common.dt;

/// This registration extension allows relying parties to specify a credential
/// protection policy when creating a credential.
credProtect: ?fido.ctap.extensions.CredentialCreationPolicy = null,

/// This extension is used by the platform to retrieve a symmetric secret from
/// the authenticator when it needs to encrypt or decrypt data using that symmetric
/// secret. This symmetric secret is scoped to a credential. The authenticator
/// and the platform each only have the part of the complete secret to prevent
/// offline attacks.
@"hmac-secret": ?fido.ctap.extensions.HmacSecret = null,

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: anytype) !void {
    return cbor.stringify(self, .{
        .allocator = options.allocator,
        .ignore_override = true,
        .field_settings = &.{
            .{ .name = "credProtect", .value_options = .{ .enum_serialization_type = .Integer } },
        },
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .ignore_override = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "credProtect", .value_options = .{ .enum_serialization_type = .Integer } },
        },
    });
}

test "hmac secret extension #1" {
    const allocator = std.testing.allocator;

    const x = @This(){ .@"hmac-secret" = .{ .create = true } };

    var a = std.Io.Writer.Allocating.init(allocator);
    defer a.deinit();

    try cbor.stringify(&x, .{}, &a.writer);

    try std.testing.expectEqualSlices(u8, "\xa1\x6b\x68\x6d\x61\x63\x2d\x73\x65\x63\x72\x65\x74\xf5", a.written());
}

test "hmac secret extension #2" {
    const allocator = std.testing.allocator;

    const x = @This(){ .@"hmac-secret" = .{ .create = false } };

    var a = std.Io.Writer.Allocating.init(allocator);
    defer a.deinit();

    try cbor.stringify(&x, .{}, &a.writer);

    try std.testing.expectEqualSlices(u8, "\xa1\x6b\x68\x6d\x61\x63\x2d\x73\x65\x63\x72\x65\x74\xf4", a.written());
}

test "hmac secret extension #3" {
    const allocator = std.testing.allocator;

    const k = cbor.cose.Key{
        .kty = .Ec2,
        .alg = .EcdhEsHkdf256,
        .crv = .P256,
        .x = try allocator.dupe(u8, "\x0d\xe6\x47\x97\x75\xc5\xb7\x04\xbf\x78\x00\x73\x80\x9d\xe1\xb3\x6a\x29\x13\x2e\x18\x77\x09\xc1\xe3\x64\xf2\x99\xf8\x84\x77\x69"),
        .y = try allocator.dupe(u8, "\x3b\xbe\x9b\xed\xcc\x1a\xc8\x32\x8b\xa6\x39\x7a\x5f\x46\xaf\x85\xfc\x7c\x51\xb3\x5b\xed\xfd\x9e\x3e\x47\xac\x6f\x34\x24\x8b\x35"),
    };
    defer k.deinit(allocator);

    const x = @This(){ .@"hmac-secret" = .{ .get = .{
        .keyAgreement = k,
        .saltEnc = (try dt.ABS64B.fromSlice("\x59\xe1\x95\xfc\x58\xc6\x14\xc0\x7c\x99\xf5\x87\x49\x5f\x37\x48\x71\xe9\x87\x3a\xd3\x7d\x5b\xca\x1e\xed\x20\x09\x26\xc3\xc6\xba\x52\x8d\x77\xa4\x8a\xf9\x59\x2b\xd7\xe7\xa8\x80\x51\x88\x7f\x21\x4e\x13\xcf\xdf\x40\x6c\x3a\x1c\x57\xd5\x29\xba\xbf\x98\x7d\x4a")).?,
        .saltAuth = (try dt.ABS32B.fromSlice("\x17\xb9\x3f\x3b\xdb\x95\x38\x0e\xd5\x12\xec\x6f\x54\x2c\xe1\x40")).?,
    } } };

    var a = std.Io.Writer.Allocating.init(allocator);
    defer a.deinit();

    try cbor.stringify(&x, .{}, &a.writer);

    try std.testing.expectEqualSlices(u8, "\xa1\x6b\x68\x6d\x61\x63\x2d\x73\x65\x63\x72\x65\x74\xa3\x01\xa5\x01\x02\x03\x38\x18\x20\x01\x21\x58\x20\x0d\xe6\x47\x97\x75\xc5\xb7\x04\xbf\x78\x00\x73\x80\x9d\xe1\xb3\x6a\x29\x13\x2e\x18\x77\x09\xc1\xe3\x64\xf2\x99\xf8\x84\x77\x69\x22\x58\x20\x3b\xbe\x9b\xed\xcc\x1a\xc8\x32\x8b\xa6\x39\x7a\x5f\x46\xaf\x85\xfc\x7c\x51\xb3\x5b\xed\xfd\x9e\x3e\x47\xac\x6f\x34\x24\x8b\x35\x02\x58\x40\x59\xe1\x95\xfc\x58\xc6\x14\xc0\x7c\x99\xf5\x87\x49\x5f\x37\x48\x71\xe9\x87\x3a\xd3\x7d\x5b\xca\x1e\xed\x20\x09\x26\xc3\xc6\xba\x52\x8d\x77\xa4\x8a\xf9\x59\x2b\xd7\xe7\xa8\x80\x51\x88\x7f\x21\x4e\x13\xcf\xdf\x40\x6c\x3a\x1c\x57\xd5\x29\xba\xbf\x98\x7d\x4a\x03\x50\x17\xb9\x3f\x3b\xdb\x95\x38\x0e\xd5\x12\xec\x6f\x54\x2c\xe1\x40", a.written());
}
