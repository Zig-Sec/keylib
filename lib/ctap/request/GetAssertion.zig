const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");
const dt = fido.common.dt;

const PinUvAuthParam = fido.ctap.pinuv.common.PinUvAuthParam;
const PinProtocol = fido.ctap.pinuv.common.PinProtocol;

const ClientDataHash = fido.ctap.crypto.ClientDataHash;

/// Relying party identifier.
rpId: dt.ABS128T, // 1
/// Hash of the serialized client data collected by the host.
clientDataHash: ClientDataHash, // 2
/// A sequence of PublicKeyCredentialDescriptor structures, each
/// denoting a credential, as specified in [WebAuthN]. If this parameter is
/// present and has 1 or more entries, the authenticator MUST only generate
/// an assertion using one of the denoted credentials.
allowList: ?dt.ABSPublicKeyCredentialDescriptor = null, // 3
extensions: ?fido.ctap.extensions.Extensions = null, // 4
/// Parameters to influence authenticator operation.
options: ?fido.common.AuthenticatorOptions = null, // 5
/// Result of calling authenticate(pinUvAuthToken, clientDataHash)
pinUvAuthParam: ?PinUvAuthParam = null, // 6
/// PIN protocol version selected by client.
pinUvAuthProtocol: ?PinProtocol = null,
enterpriseAttestation: ?u64 = null,
attestationFormatsPreference: ?dt.ABSAttestationStatementFormatIdentifiers = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    if (self.extensions) |exts| {
        if (exts.@"hmac-secret") |hms| {
            switch (hms) {
                .get => |hms_get| {
                    hms_get.keyAgreement.deinit(allocator);
                },
                else => {},
            }
        }
    }
}

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
            .{ .name = "rpId", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
            .{ .name = "clientDataHash", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "allowList", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "extensions", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "options", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "7", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "enterpriseAttestation", .field_options = .{ .alias = "8", .serialization_type = .Integer } },
            .{ .name = "attestationFormatsPreference", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
        },
    }, out);
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .ignore_override = true,
        .field_settings = &.{
            .{ .name = "rpId", .field_options = .{ .alias = "1", .serialization_type = .Integer }, .value_options = .{ .slice_serialization_type = .TextString } },
            .{ .name = "clientDataHash", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "allowList", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "extensions", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "options", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthParam", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "7", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
            .{ .name = "enterpriseAttestation", .field_options = .{ .alias = "8", .serialization_type = .Integer } },
            .{ .name = "attestationFormatsPreference", .field_options = .{ .alias = "9", .serialization_type = .Integer }, .value_options = .{ .enum_serialization_type = .Integer } },
        },
    });
}

test "get assertion parse 1" {
    const payload = "\xa6\x01\x6b\x77\x65\x62\x61\x75\x74\x68\x6e\x2e\x69\x6f\x02\x58\x20\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b\x03\x81\xa2\x62\x69\x64\x58\x40\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x05\xa1\x62\x75\x70\xf4\x06\x58\x20\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10\x07\x02";

    const di = try cbor.DataItem.new(payload);

    const get_assertion_param = try cbor.parse(@This(), di, .{});

    try std.testing.expectEqualStrings("webauthn.io", get_assertion_param.rpId.get());
    try std.testing.expectEqualSlices(u8, "\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b", &get_assertion_param.clientDataHash);
    try std.testing.expectEqual(@as(usize, @intCast(1)), get_assertion_param.allowList.?.len);
    try std.testing.expectEqualSlices(u8, "\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0", get_assertion_param.allowList.?.get()[0].id.get());
    try std.testing.expectEqual(fido.common.PublicKeyCredentialType.@"public-key", get_assertion_param.allowList.?.get()[0].type);
    try std.testing.expectEqual(false, get_assertion_param.options.?.up.?);
    try std.testing.expectEqualSlices(u8, "\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10", get_assertion_param.pinUvAuthParam.?.get());
    try std.testing.expectEqual(PinProtocol.V2, get_assertion_param.pinUvAuthProtocol.?);
}

test "get assertion stringify 1" {
    const allocator = std.testing.allocator;
    var x = std.Io.Writer.Allocating.init(allocator);
    defer x.deinit();

    const payload = "\xa6\x01\x6b\x77\x65\x62\x61\x75\x74\x68\x6e\x2e\x69\x6f\x02\x58\x20\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b\x03\x81\xa2\x62\x69\x64\x58\x40\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x05\xa1\x62\x75\x70\xf4\x06\x58\x20\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10\x07\x02";

    const gap = @This(){
        .rpId = (try dt.ABS128T.fromSlice("webauthn.io")).?,
        .clientDataHash = "\x6e\x0c\xb5\xf9\x7c\xae\xb8\xbf\x79\x7a\x62\x14\xc7\x19\x1c\x80\x8f\xe5\xa5\x50\x21\xf9\xfb\x76\x6e\x81\x83\xcd\x8a\x0d\x55\x0b".*,
        .allowList = (try dt.ABSPublicKeyCredentialDescriptor.fromSlice(&.{try fido.common.PublicKeyCredentialDescriptor.new("\xf9\xff\xff\xff\x95\xea\x72\x74\x2f\xa6\x03\xc3\x51\x9f\x9c\x17\xc0\xff\x81\xc4\x5d\xbb\x46\xe2\x3c\xff\x6f\xc1\xd0\xd5\xb3\x64\x6d\x49\x5c\xb1\x1b\x80\xe5\x78\x88\xbf\xba\xe3\x89\x8d\x69\x85\xfc\x19\x6c\x43\xfd\xfc\x2e\x80\x18\xac\x2d\x5b\xb3\x79\xa1\xf0", .@"public-key", null)})).?,
        .options = .{
            .up = false,
            .rk = null,
            .uv = null,
        },
        .pinUvAuthParam = (try dt.ABS32B.fromSlice("\x30\x5b\x38\x2d\x1c\xd9\xb9\x71\x4d\x51\x98\x30\xe5\xb0\x02\xcb\x6c\x38\x25\xbc\x05\xf8\x7e\xf1\xbc\xda\x36\x4d\x2d\x4d\xb9\x10")).?,
        .pinUvAuthProtocol = .V2,
    };

    try cbor.stringify(gap, .{}, &x.writer);

    try std.testing.expectEqualSlices(u8, payload, x.written());
}

test "get assertion parse 2" {
    const payload = "\xa6\x01\x78\x2e\x77\x65\x62\x61\x75\x74\x68\x6e\x2d\x70\x61\x73\x73\x6b\x65\x79\x73\x2d\x70\x72\x66\x2d\x64\x65\x6d\x6f\x2e\x65\x78\x70\x6c\x6f\x72\x65\x2e\x63\x6f\x72\x62\x61\x64\x6f\x2e\x63\x6f\x6d\x02\x58\x20\x0d\xcc\xa3\x8c\xa4\xde\xd1\x73\x1c\xb6\x54\x3d\xe3\x47\x92\xe3\x19\xe4\x8d\xa2\xbc\x1f\x8d\x45\x14\x78\x67\x26\x80\x77\xdd\xa4\x03\x81\xa2\x62\x69\x64\x58\x24\x30\x31\x61\x31\x33\x31\x61\x62\x2d\x39\x61\x65\x38\x2d\x37\x37\x63\x66\x2d\x61\x66\x32\x33\x2d\x36\x33\x66\x64\x63\x66\x34\x39\x65\x31\x37\x39\x64\x74\x79\x70\x65\x6a\x70\x75\x62\x6c\x69\x63\x2d\x6b\x65\x79\x04\xa1\x6b\x68\x6d\x61\x63\x2d\x73\x65\x63\x72\x65\x74\xa4\x01\xa5\x01\x02\x03\x38\x18\x20\x01\x21\x58\x20\x1b\x98\xe4\x93\x04\xa2\xd7\x5b\x22\x9d\x94\x06\xff\x7d\xe0\x78\xd5\xb7\x1b\xa6\x81\x0a\x48\x4e\xf7\xfe\x3f\xc6\xbf\x23\xcb\x18\x22\x58\x20\xf4\xe1\x34\xd4\x17\x80\xc7\xa9\xc7\xcb\xd1\x05\xd8\x64\x01\x5b\xde\xb6\x94\x35\xd1\x7d\xa9\x88\xce\x84\x82\xb2\x90\xb6\xb4\x1c\x02\x58\x30\xa3\xe9\xa5\x16\xba\x52\x4e\xd8\x73\x7d\x4d\x41\x8c\x29\xfd\x1e\xf7\x79\x6d\x73\x77\xfd\x0c\x90\xf8\x21\x54\x21\xe9\xdf\x81\x4e\xaa\xbf\x11\xc6\x3d\xd4\x40\x06\x33\x5f\x38\xef\x66\x09\xd3\x03\x03\x58\x20\xa2\xca\x34\xb3\x2d\x39\xd2\x26\x97\xc9\x82\xc2\xd8\xe2\xc9\x3f\x1e\x0c\xcf\xad\x45\xef\x3d\xe5\xca\x80\x1a\x65\x97\x80\xdd\x4d\x04\x02\x06\x58\x20\xd2\xf1\xb1\xa9\x4d\x76\xec\x76\x56\x9d\x92\x7f\x42\x26\xcf\xcb\x56\x92\xbb\xc1\x59\x58\xca\x1f\x07\x7f\xd7\x30\xa7\xcf\xd4\xcb\x07\x02";

    const di = try cbor.DataItem.new(payload);

    const get_assertion_param = try cbor.parse(@This(), di, .{
        .allocator = std.testing.allocator,
    });
    defer get_assertion_param.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, "\xa3\xe9\xa5\x16\xba\x52\x4e\xd8\x73\x7d\x4d\x41\x8c\x29\xfd\x1e\xf7\x79\x6d\x73\x77\xfd\x0c\x90\xf8\x21\x54\x21\xe9\xdf\x81\x4e\xaa\xbf\x11\xc6\x3d\xd4\x40\x06\x33\x5f\x38\xef\x66\x09\xd3\x03", get_assertion_param.extensions.?.@"hmac-secret".?.get.saltEnc.get());

    try std.testing.expectEqualSlices(u8, "\xa2\xca\x34\xb3\x2d\x39\xd2\x26\x97\xc9\x82\xc2\xd8\xe2\xc9\x3f\x1e\x0c\xcf\xad\x45\xef\x3d\xe5\xca\x80\x1a\x65\x97\x80\xdd\x4d", get_assertion_param.extensions.?.@"hmac-secret".?.get.saltAuth.get());
}
