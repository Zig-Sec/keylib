const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../../main.zig");

/// Report a list of the authenticators supported protocol versions and
/// extensions, its AAGUID, and other aspects of its overall capabilities.
pub fn authenticatorGetInfo(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.Io.Writer,
) fido.ctap.StatusCodes {
    _ = request;

    const settings = auth.callbacks.read_settings(
        auth.allocator,
        auth.io,
    );

    auth.settings.minPINLength = settings.min_pin_length;
    auth.settings.forcePINChange = settings.force_pin_change;
    auth.settings.options.alwaysUv = settings.always_uv;

    cbor.stringify(auth.settings, .{}, out) catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    return fido.ctap.StatusCodes.ctap1_err_success;
}
