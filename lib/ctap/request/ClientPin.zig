//! Parameters of the client pin command

const std = @import("std");
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

const cbor = @import("zbor");
const fido = @import("../../main.zig");
const dt = fido.common.dt;

/// pinUvAuthProtocol: PIN protocol version chosen by the client.
pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,
/// subCommand: The authenticator Client PIN sub command currently
/// being requested.
subCommand: fido.ctap.pinuv.common.SubCommand,
/// keyAgreement: Public key of platformKeyAgreementKey. The
/// COSE_Key-encoded public key MUST contain the optional "alg"
/// parameter and MUST NOT contain any other optional parameters.
/// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value.
keyAgreement: ?cbor.cose.Key = null,
/// pinUvAuth: HMAC-SHA-256 of encrypted contents
/// using sharedSecret. See Setting a new PIN, Changing existing
/// PIN and Getting pinToken from the authenticator for more details.
pinUvAuthParam: ?dt.ABS32B = null,
/// newPinEnc: Encrypted new PIN using sharedSecret. Encryption is
/// done over UTF-8 representation of new PIN.
newPinEnc: ?dt.ABS80B = null,
/// pinHashEnc: Encrypted SHA-256 of PIN using sharedSecret.
pinHashEnc: ?dt.ABS32B = null,
/// permissions: Bitfield of permissions. If present, MUST NOT be 0.
permissions: ?u32 = null,
/// rpId: The RP ID to assign as the permissions RP ID.
rpId: ?dt.ABS128T = null,

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: *std.Io.Writer) !void {
    _ = options;

    try cbor.stringify(self.*, .{
        .field_settings = &.{
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "subCommand", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "keyAgreement", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "newPinEnc", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "pinHashEnc", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "permissions", .field_options = .{ .alias = "9", .serialization_type = .Integer } },
            .{ .name = "rpId", .field_options = .{ .alias = "10", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
        },
        .ignore_override = true,
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .field_settings = &.{
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "subCommand", .field_options = .{ .alias = "2", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "keyAgreement", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "newPinEnc", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "pinHashEnc", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "permissions", .field_options = .{ .alias = "9", .serialization_type = .Integer } },
            .{ .name = "rpId", .field_options = .{ .alias = "10", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
        },
        .ignore_override = true,
    });
}

pub fn mcPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x01 != 0 else false;
}

pub fn gaPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x02 != 0 else false;
}

pub fn cmPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x04 != 0 else false;
}

pub fn bePermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x08 != 0 else false;
}

pub fn lbwPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x10 != 0 else false;
}

pub fn acfgPermissionSet(self: *const @This()) bool {
    return if (self.permissions) |p| p & 0x20 != 0 else false;
}
