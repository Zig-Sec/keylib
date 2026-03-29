const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const PublicKeyCredentialDescriptor = fido.common.PublicKeyCredentialDescriptor;
const User = fido.common.User;

/// PublicKeyCredentialDescriptor structure containing the
/// credential identifier whose private key was used to generate the
/// assertion. May be omitted if the allowList has exactly one Credential.
credential: PublicKeyCredentialDescriptor, // 1
/// authData: The signed-over contextual bindings made by the authenticator,
/// as specified in [WebAuthN].
authData: []const u8, // 2
/// signature: The assertion signature produced by the authenticator, as
/// specified in [WebAuthN].
signature: []const u8, // 3
/// PublicKeyCredentialUserEntity structure containing the user account
/// information.
///
/// FIDO Devices: For discoverable credentials on FIDO devices, at least
/// user "id" is mandatory.
///
/// For single account per RP case, authenticator returns "id" field to
/// the platform which will be returned to the WebAuthn layer.
///
/// For multiple accounts per RP case, where the authenticator does not
/// have a display, authenticator returns "id" as well as other fields
/// to the platform.
user: ?User = null, // 4
/// numberOfCredentials: Total number of account credentials for the RP.
/// This member is required when more than one account for the RP and the
/// authenticator does not have a display. Omitted when returned for the
/// authenticatorGetNextAssertion method.
numberOfCredentials: ?u64 = null, // 5
/// Indicates that a credential was selected by the user via interaction
/// directly with the authenticator, and thus the platform does not need
/// to confirm the credential.
userSelected: ?bool = null, // 6
/// The contents of the associated largeBlobKey if present for the asserted
/// credential, and if largeBlobKey was true in the extensions input.
largeBlobKey: ?[]const u8 = null, // 7

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    allocator.free(self.authData);
    allocator.free(self.signature);

    if (self.largeBlobKey) |lbk| {
        allocator.free(lbk);
    }
}

pub fn cborStringify(self: *const @This(), options: cbor.Options, out: *std.Io.Writer) !void {
    _ = options;

    try cbor.stringify(
        self,
        .{
            .field_settings = &.{
                .{ .name = "credential", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "authData", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "signature", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "user", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
                .{ .name = "numberOfCredentials", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
                .{ .name = "userSelected", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
                .{ .name = "largeBlobKey", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
            },
            .ignore_override = true,
        },
        out,
    );
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    return try cbor.parse(@This(), item, .{
        .allocator = options.allocator,
        .ignore_override = true, // prevent infinite loops
        .field_settings = &.{
            .{ .name = "credential", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
            .{ .name = "authData", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
            .{ .name = "signature", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
            .{ .name = "user", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
            .{ .name = "numberOfCredentials", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            .{ .name = "userSelected", .field_options = .{ .alias = "6", .serialization_type = .Integer } },
            .{ .name = "largeBlobKey", .field_options = .{ .alias = "7", .serialization_type = .Integer } },
        },
    });
}
