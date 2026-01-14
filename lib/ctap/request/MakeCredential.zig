const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");
const dt = fido.common.dt;

const RelyingParty = fido.common.RelyingParty;
const User = fido.common.User;
const PublicKeyCredentialParameters = fido.common.PublicKeyCredentialParameters;
const PublicKeyCredentialDescriptor = fido.common.PublicKeyCredentialDescriptor;
const AuthenticatorOptions = fido.common.AuthenticatorOptions;

const PinUvAuthParam = fido.ctap.pinuv.common.PinUvAuthParam;
const PinProtocol = fido.ctap.pinuv.common.PinProtocol;

const ClientDataHash = fido.ctap.crypto.ClientDataHash;

/// Hash of the ClientData contextual binding
clientDataHash: ClientDataHash,
/// PublicKeyCredentialRpEntity
rp: RelyingParty,
/// PublicKeyCredentialUserEntity
user: User,
/// A sequence of CBOR maps
pubKeyCredParams: dt.ABSPublicKeyCredentialParameters,
/// excludeList: A sequence of PublicKeyCredentialDescriptor structures.
/// The authenticator returns an error if the authenticator already contains
/// one of the credentials enumerated in this sequence.
excludeList: ?dt.ABSPublicKeyCredentialDescriptor = null,
extensions: ?fido.ctap.extensions.Extensions = null,
/// authenticator options: Parameters to influence authenticator operation.
options: ?AuthenticatorOptions = null,
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?PinUvAuthParam = null,
/// PIN protocol version chosen by the client.
pinUvAuthProtocol: ?PinProtocol = null,
enterpriseAttestation: ?u64 = null,

pub fn requestsUv(self: *const @This()) bool {
    return self.options != null and self.options.?.uv != null and self.options.?.uv.?;
}

pub fn requestsRk(self: *const @This()) bool {
    return self.options != null and self.options.?.rk != null and self.options.?.rk.?;
}

pub fn requestsUp(self: *const @This()) bool {
    // if up missing treat it as being present with the value true
    return if (self.options != null and self.options.?.up != null) self.options.?.up.? else true;
}

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: *std.Io.Writer) !void {
    return cbor.stringify(self, .{
        .allocator = options.allocator,
        .ignore_override = true,
        .field_settings = &.{
            .{ .name = "clientDataHash", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
            .{ .name = "rp", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "user", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "pubKeyCredParams", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "excludeList", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "extensions", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "options", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "8", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "enterpriseAttestation", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
        },
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .ignore_override = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "clientDataHash", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
            .{ .name = "rp", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "user", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "pubKeyCredParams", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "excludeList", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "extensions", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "options", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "8", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "enterpriseAttestation", .field_options = .{ .alias = "10", .serialization_type = .Integer } },
        },
    });
}

test "make credential parse 1" {
    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const di = try cbor.DataItem.new(payload);

    const mcp = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqualSlices(u8, "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c", &mcp.clientDataHash);
    try std.testing.expectEqualSlices(u8, "localhost", mcp.rp.id.get());
    try std.testing.expectEqualSlices(u8, "sweet home localhost", mcp.rp.name.?.get());
    try std.testing.expectEqualSlices(u8, "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49", mcp.user.id.get());
    try std.testing.expectEqualSlices(u8, "john smith", mcp.user.name.?.get());
    try std.testing.expectEqualSlices(u8, "jsmith", mcp.user.displayName.?.get());
    try std.testing.expectEqual(mcp.pubKeyCredParams.get()[0].alg, cbor.cose.Algorithm.Es256);
    try std.testing.expectEqual(mcp.pubKeyCredParams.get()[0].type, .@"public-key");
}

test "make credential stringify 1" {
    const allocator = std.testing.allocator;
    var x = std.Io.Writer.Allocating.init(allocator);
    defer x.deinit();

    const payload = "\xa4\x01\x58\x20\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c\x02\xa2\x62\x69\x64\x69\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x64\x6e\x61\x6d\x65\x74\x73\x77\x65\x65\x74\x20\x68\x6f\x6d\x65\x20\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x03\xa3\x62\x69\x64\x58\x20\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49\x64\x6e\x61\x6d\x65\x6a\x6a\x6f\x68\x6e\x20\x73\x6d\x69\x74\x68\x6b\x64\x69\x73\x70\x6c\x61\x79\x4e\x61\x6d\x65\x66\x6a\x73\x6d\x69\x74\x68\x04\x81\xa2\x63\x61\x6c\x67\x26\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79";

    const mcp = @This(){
        .clientDataHash = "\xc0\x39\x91\xac\x3d\xff\x02\xba\x1e\x52\x0f\xc5\x9b\x2d\x34\x77\x4a\x64\x1a\x4c\x42\x5a\xbd\x31\x3d\x93\x10\x61\xff\xbd\x1a\x5c".*,
        .rp = try RelyingParty.new(
            "localhost",
            "sweet home localhost",
        ),
        .user = try User.new(
            "\x78\x1c\x78\x60\xad\x88\xd2\x63\x32\x62\x2a\xf1\x74\x5d\xed\xb2\xe7\xa4\x2b\x44\x89\x29\x39\xc5\x56\x64\x01\x27\x0d\xbb\xc4\x49",
            "john smith",
            "jsmith",
        ),
        .pubKeyCredParams = (try dt.ABSPublicKeyCredentialParameters.fromSlice(&.{
            .{ .alg = .Es256, .type = .@"public-key" },
        })).?,
    };

    try cbor.stringify(mcp, .{}, &x.writer);

    try std.testing.expectEqualSlices(u8, payload, x.written());
}
