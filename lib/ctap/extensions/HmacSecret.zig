const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");
const dt = fido.common.dt;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const HmacSecretTag = enum { create, get, output };

pub const HmacSecretGet = struct {
    /// Public key of platform key-agreement key (also used by pinUv protocol)
    keyAgreement: cbor.cose.Key,
    /// Encryption of the one or two salts (called salt1 (32 bytes) and salt2 (32 bytes))
    /// using the shared secret as follows:
    ///     One salt case: encrypt(shared secret, salt1)
    ///     Two salt case: encrypt(shared secret, salt1 || salt2)
    saltEnc: dt.ABS64B,
    /// authenticate(shared secret, saltEnc)
    saltAuth: dt.ABS32B,
    /// As selected when getting the shared secret. CTAP2.1 platforms MUST include this
    /// parameter if the value of pinUvAuthProtocol is not 1.
    pinUvAuthProtocol: ?fido.ctap.pinuv.common.PinProtocol = null,

    pub fn generate(
        self: *const @This(),
        status: *fido.ctap.StatusCodes,
        auth: *fido.ctap.authenticator.Auth,
        cred: *const fido.ctap.authenticator.Credential,
        uv: bool,
    ) ?dt.ABS64B {
        // Call decapsulate on the provided platform key-agreement key
        const shared_secret = auth.token.ecdh(self.keyAgreement) catch {
            status.* = fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            return null;
        };

        // Verify saltEnc with the siganture saltAuth
        if (auth.token.verify( // salt1 || salt2
            shared_secret.get(),
            self.saltEnc.get(),
            self.saltAuth.get(),
        )) {
            status.* = .ctap2_err_pin_auth_invalid;
            return null;
        }

        var r: ?dt.ABS64B = null;

        var cred_random: []const u8 = undefined;
        if (uv and cred.cred_random_with_uv != null) {
            cred_random = cred.cred_random_with_uv.?[0..];
        } else if (!uv and cred.cred_random_without_uv != null) {
            cred_random = cred.cred_random_without_uv.?[0..];
        } else {
            // If the authenticator cannot find corresponding CredRandom
            // associated with the credential, authenticator ignores this
            // extension and does not add any response from this extension
            // to "extensions" field of the authenticatorGetAssertion response.
            return null;
        }

        if (self.saltEnc.len == 64) {
            // Decrypt saltEnc to obtain
            var @"salt1 || salt2": [64]u8 = .{0} ** 64;
            auth.token.decrypt(
                shared_secret.get(),
                &@"salt1 || salt2",
                self.saltEnc.get(),
            );

            const salt1 = @"salt1 || salt2"[0..32];
            const salt2 = @"salt1 || salt2"[32..];

            var output1: [32]u8 = undefined;
            HmacSha256.create(output1[0..32], salt1, cred_random);

            var output2: [32]u8 = undefined;
            HmacSha256.create(output2[0..32], salt2, cred_random);

            var in: [64]u8 = undefined;
            @memcpy(in[0..32], output1[0..]);
            @memcpy(in[32..], output2[0..]);

            var out: [64]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret.get(),
                &out,
                &in,
            );

            r = dt.ABS64B.fromSlice(&out) catch unreachable;
        } else if (self.saltEnc.len == 32) {
            // Decrypt saltEnc to obtain
            var salt1: [32]u8 = undefined;
            auth.token.decrypt(
                shared_secret.get(),
                &salt1,
                self.saltEnc.get(),
            );

            var output1: [32]u8 = undefined;
            HmacSha256.create(output1[0..32], &salt1, cred_random);

            var out: [32]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret.get(),
                &out,
                &output1,
            );

            r = dt.ABS64B.fromSlice(&out) catch unreachable;
        } else {
            status.* = .ctap1_err_invalid_parameter;
            return null;
        }

        return r;
    }
};

pub const HmacSecret = union(HmacSecretTag) {
    create: bool,
    get: HmacSecretGet,
    output: dt.ABS64B,

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: *std.Io.Writer) !void {
        _ = options;

        try cbor.stringify(self.*, .{
            .field_settings = &.{
                .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "saltEnc", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "saltAuth", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            },
            .ignore_override = true,
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .allocator = options.allocator,
            .field_settings = &.{
                .{ .name = "keyAgreement", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "saltEnc", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "saltAuth", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "pinUvAuthProtocol", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            },
            .ignore_override = true,
        });
    }
};
