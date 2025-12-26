const std = @import("std");
const fido = @import("../../main.zig");
const cbor = @import("zbor");
const dt = fido.common.dt;

/// Credential ID
id: dt.ABS64B,

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
