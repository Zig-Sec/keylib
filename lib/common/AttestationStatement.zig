//! Attestation statement is a specific type of signed data object, containing statements
//! about a public key credential itself and the authenticator that created it. It
//! contains an attestation signature created using the key of the attesting authority
//! (except for the case of self attestation, when it is created using the credential
//! private key)

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../main.zig");
const dt = @import("data_types.zig");

pub const AttestationStatement = union(fido.common.AttestationStatementFormatIdentifiers) {
    /// This is a WebAuthn optimized attestation statement format. It uses a very compact
    /// but still extensible encoding method. It is implementable by authenticators with
    /// limited resources (e.g., secure elements).
    @"packed": struct { // basic, self, AttCA
        /// A COSEAlgorithmIdentifier containing the identifier of the algorithm used
        /// to generate the attestation signature.
        alg: cbor.cose.Algorithm,
        /// A byte string containing the attestation signature.
        ///
        /// TODO: A ABS256B can hold signatures up to 2048 bytes, e.g., RSA-2048.
        /// This has to be modified to accomodate larger signatures.
        sig: dt.ABS256B,
        // The elements of this array contain attestnCert and its certificate chain (if any),
        // each encoded in X.509 format. The attestation certificate attestnCert MUST be
        // the first element in the array.
        x5c: ?[]const []const u8 = null,
    },
    tpm: struct {}, // TODO: implement
    @"android-key": struct {}, // TODO: implement
    @"android-safetynet": struct {}, // TODO: implement
    @"fido-u2f": struct {}, // TODO: implement
    apple: struct {}, // TODO: implement
    /// The none attestation statement format is used to replace any authenticator-provided
    /// attestation statement when a WebAuthn Relying Party indicates it does not wish to
    /// receive attestation information, see § 5.4.7 Attestation Conveyance Preference
    /// Enumeration (enum AttestationConveyancePreference).
    none: struct {}, // no attestation

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        switch (self.*) {
            .@"packed" => |p| {
                if (p.x5c) |x5c| {
                    for (x5c) |v| allocator.free(v);
                    allocator.free(x5c);
                }
            },
            else => {},
        }
    }

    pub fn cborStringify(self: *const @This(), options: cbor.Options, out: *std.Io.Writer) !void {
        return cbor.stringify(self, .{
            .allocator = options.allocator,
            .ignore_override = true,
            .field_settings = &.{
                .{ .name = "alg", .value_options = .{ .enum_serialization_type = .Integer } },
            },
        }, out);
    }

    pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
        return try cbor.parse(@This(), item, .{
            .allocator = options.allocator,
            .ignore_override = true, // prevent infinite loops
            .field_settings = &.{
                .{ .name = "alg", .value_options = .{ .enum_serialization_type = .Integer } },
            },
        });
    }
};
