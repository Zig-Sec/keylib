const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");
const dt = fido.common.dt;

/// Credential ID
id: dt.ABS128B,

/// User information
user: fido.common.User,

/// Information about the relying party
rp: fido.common.RelyingParty,

/// Number of signatures issued using the given credential
sign_count: u64,

key: cbor.cose.Key,

/// Epoch time stamp this credential was created
created: i64,

/// Is this credential discoverable or not
///
/// This is kind of stupid but authenticatorMakeCredential
/// docs state, that you're not allowed to create a discoverable
/// credential if not explicitely requested. The docs also state
/// that you're allowed to keep (some) state, e.g., store the key.
discoverable: bool = false,

/// The BE flag SHALL be set if and only if the credential
/// is a multi-device credential. This value MUST NOT change
/// after a registration ceremony.
be: bool = false,

/// The BS flag SHALL be set if and only if the credential is a
/// multi-device credential and is currently backed up. If the
/// backup status of a credential is uncertain or the authenticator
/// suspects a problem with the backed up credential, the BS flag
/// SHOULD NOT be set.
bs: bool = false,

policy: fido.ctap.extensions.CredentialCreationPolicy = .userVerificationOptional,

// HMAC Secret Extension BEGIN
/// Belongs to hmac secret
cred_random_with_uv: ?[32]u8 = null,

/// Belongs to hmac secret
cred_random_without_uv: ?[32]u8 = null,
// HMAC Secret Extension END

pub fn desc(_: void, lhs: @This(), rhs: @This()) bool {
    return lhs.created > rhs.created;
}

pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
    self.key.deinit(allocator);

    if (self.cred_random_with_uv) |*v| {
        std.crypto.secureZero(u8, v);
    }

    if (self.cred_random_without_uv) |*v| {
        std.crypto.secureZero(u8, v);
    }
}

pub fn copy(self: *const @This(), allocator: std.mem.Allocator) !@This() {
    return .{
        .id = self.id,
        .user = self.user,
        .rp = self.rp,
        .sign_count = self.sign_count,
        .key = try self.key.copy(allocator),
        .created = self.created,
        .discoverable = self.discoverable,
        .be = self.be,
        .bs = self.bs,
        .policy = self.policy,
        .cred_random_with_uv = self.cred_random_with_uv,
        .cred_random_without_uv = self.cred_random_without_uv,
    };
}
