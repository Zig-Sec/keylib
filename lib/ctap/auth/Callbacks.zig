//! Callbacks provided by the underlying platform/ the user
//!
//! The callbacks are required to keep the library platform
//! agnostic.

const std = @import("std");
const fido = @import("../../main.zig");
const cks = @import("cks");
const dt = fido.common.dt;

pub const CallbackError = error{
    Success,
    DoesAlreadyExist,
    DoesNotExist,
    KeyStoreFull,
    OutOfMemory,
    Timeout,
    Other,
};

pub const Error = enum(i32) {
    SUCCESS = 0,
    DoesAlreadyExist = -1,
    DoesNotExist = -2,
    KeyStoreFull = -3,
    OutOfMemory = -4,
    Timeout = -5,
    Other = -6,
};

/// Result value of the `up` callback
pub const UpResult = enum(i32) {
    /// The user has denied the action
    Denied = 0,
    /// The user has accepted the action
    Accepted = 1,
    /// The user presence check has timed out
    Timeout = 2,
};

/// Result value of the `uv` callback
pub const UvResult = enum(i32) {
    /// The user has denied the action
    Denied = 0,
    /// The user has accepted the action
    Accepted = 1,
    /// The user has accepted the action
    AcceptedWithUp = 2,
    /// The user presence check has timed out
    Timeout = 3,
};

pub const DataIterator = struct {
    d: [*c][*c]u8 = 0,
    i: usize = 0,
    allocator: std.mem.Allocator,

    pub fn next(self: *@This()) ?[]const u8 {
        if (self.d == null) return null;

        if (self.d[self.i] == null) {
            return null;
        } else {
            defer self.i += 1;
            return self.d[self.i][0..strlen(self.d[self.i])];
        }
    }

    pub fn deinit(self: *@This()) void {
        if (self.d == null) return;

        var i: usize = 0;
        while (self.d[i] != null) {
            var x = self.d[i];
            const l = strlen(x);
            // First overwrite the region with 0. This prevents sensitive information
            // from lingering in memory for longer than neccessary.
            @memset(x[0..l], 0);
            // Then free the memory
            self.allocator.free(x[0 .. l + 1]);
            i += 1;
            x = self.d[i];
        }
        self.allocator.free(self.d[0 .. i + 1]);
    }
};

inline fn strlen(s: [*c]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    return i;
}

// +++++++++++++++++++++++++++++++++++++++++++++++++++
// Callback Types
// +++++++++++++++++++++++++++++++++++++++++++++++++++

pub const UpCallback = *const fn (
    /// Information about the context (e.g., make credential)
    info: []const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: ?fido.common.User,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: ?fido.common.RelyingParty,
) UpResult;

/// Type of the User Verification (UV) callback
///
/// This callback can be backed by ANY form of
/// user verification like a password, finger
/// print, ...
pub const UvCallback = ?*const fn (
    /// Information about the context (e.g., make credential)
    info: []const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: ?fido.common.User,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: ?fido.common.RelyingParty,
    /// Optional pin hash for pin UV.
    pinHash: ?[]const u8,
) UvResult;

/// Read the first credential associated with `id` and `rp` into out
///
/// ## Argument options
///
/// * `id = null` and `rp = null` - Return all credential entries.
/// * `id != null` and `rp = null` - Return the entry with the specified `id`. This can be a credential or settings.
/// * `id = null` and `rp != null` - Return all credentials associated with the given `rp` ID.
pub const ReadFirstCallback = *const fn (
    id: ?dt.ABS64B,
    rp: ?dt.ABS128T,
    hash: ?[32]u8,
) CallbackError!fido.ctap.authenticator.Credential;

/// This function can be called multiple times after calling the ReadFirstCallback to obtain the remaining credentials.
pub const ReadNextCallback = *const fn () CallbackError!fido.ctap.authenticator.Credential;

pub const ReadSettingsCallback = *const fn () fido.ctap.authenticator.Meta;
pub const WriteSettingsCallback = *const fn (data: fido.ctap.authenticator.Meta) void;

/// Write `data` to permanent storage (e.g., database, filesystem, ...)
pub const CreateCallback = *const fn (
    data: fido.ctap.authenticator.Credential,
) CallbackError!void;

/// Delete the entry with the given `id`
///
/// Returns either Error.SUCCESS on success or an error.
pub const DeleteCallback = *const fn (
    id: [*c]const u8,
) callconv(.c) Error;

// +++++++++++++++++++++++++++++++++++++++++++++++++++
// Data Structures for CTAP2 (CBOR) commands
// +++++++++++++++++++++++++++++++++++++++++++++++++++

/// This callback signature is used for CTAP2 command-functions like:
/// * `authenticatorGetAssertion`
/// * `authenticatorMakeCredential`
pub const Ctap2CommandCallback = *const fn (
    /// Pointer to the authenticator struct
    auth: *fido.ctap.authenticator.Auth,
    /// CBOR encoded params
    params: []const u8,
    /// Writer for the respones
    *std.Io.Writer,
) fido.ctap.StatusCodes;

pub const Ctap2CommandMapping = struct {
    cmd: u8,
    cb: Ctap2CommandCallback,
};

// +++++++++++++++++++++++++++++++++++++++++++++++++++
// Some other (optional) callbacks
// +++++++++++++++++++++++++++++++++++++++++++++++++++

/// Replace the CurrentStoredPIN with a new pin.
pub const SetPin = *const fn (pin: []const u8) CallbackError!void;

// +++++++++++++++++++++++++++++++++++++++++++++++++++
// Callbacks
// +++++++++++++++++++++++++++++++++++++++++++++++++++

pub const Callbacks = struct {
    /// Request user presence
    up: UpCallback,

    /// User verification callback
    ///
    /// This callback should execute a built-in user verification method.
    ///
    /// This callback is optional. Client request with the uv flag set will
    /// fail if this callback isn't provided.
    ///
    /// Possible methods are:
    /// - Password
    /// - Finger print sensor
    /// - Pattern
    uv: UvCallback,

    read_first: ReadFirstCallback,
    read_next: ReadNextCallback,
    write: CreateCallback,
    delete: DeleteCallback,
    read_settings: ReadSettingsCallback,
    write_settings: WriteSettingsCallback,
    set_pin: ?SetPin = null,
};
