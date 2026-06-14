const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const uuid = @import("uuid");
const helper = @import("helper.zig");

pub fn authenticatorGetNextAssertion(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.Io.Writer,
) fido.ctap.StatusCodes {
    _ = request;

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Validate
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    // TODO: hardcoded?
    const seconds_30 = 30000;

    if (auth.getAssertion == null) {
        return .ctap2_err_not_allowed;
    }

    if (auth.getAssertion.?.count >= auth.getAssertion.?.total) {
        auth.getAssertion = null;
        return .ctap2_err_not_allowed;
    }

    if (auth.getAssertion.?.ts.untilNow(auth.io, .real).toMilliseconds() > seconds_30) {
        auth.getAssertion = null;
        return .ctap2_err_not_allowed;
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Get Credential
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    var selected_credential: ?fido.ctap.authenticator.Credential = null;
    defer if (selected_credential) |*c| c.deinit(auth.allocator);
    var credential = auth.callbacks.read_next() catch {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    };

    while (true) {
        var skip = false;
        const policy = credential.policy;

        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (policy == .userVerificationRequired and !auth.getAssertion.?.uv) {
            skip = true;
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (policy == .userVerificationOptionalWithCredentialIDList and auth.getAssertion.?.allowList == null and !auth.getAssertion.?.uv) {
            skip = true;
        }

        // TODO: check allow list

        if (!skip) {
            selected_credential = credential;
            auth.getAssertion.?.count += 1;
            break;
        } else {
            credential.deinit(auth.allocator);
        }

        credential = auth.callbacks.read_next() catch {
            break;
        };
    }

    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // Generate Assertion
    // +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    if (selected_credential == null) {
        std.log.err("getNextAssertion: no credential", .{});
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    }

    std.log.info("getNextAssertion: found credential\n    {s}", .{selected_credential.?.rp.id.get()});
    var write_back: bool = false;
    if (!auth.constSignCount) {
        selected_credential.?.sign_count += 1;
        write_back = true;
    }
    const usageCnt = selected_credential.?.sign_count;

    const user = if (auth.getAssertion.?.uv) blk: {
        // User identifiable information (name, DisplayName, icon)
        // inside the publicKeyCredentialUserEntity MUST NOT be returned
        // if user verification is not done by the authenticator
        break :blk selected_credential.?.user;
    } else blk: {
        break :blk fido.common.User{ .id = selected_credential.?.user.id };
    };

    var auth_data = fido.common.AuthenticatorData{
        .rpIdHash = undefined,
        .flags = .{
            .up = if (auth.getAssertion.?.up) 1 else 0,
            .rfu1 = 0,
            .uv = if (auth.getAssertion.?.uv) 1 else 0,
            .be = if (selected_credential.?.be) 1 else 0,
            .bs = if (selected_credential.?.bs) 1 else 0,
            .rfu2 = 0,
            .at = 0,
            .ed = 0,
        },
        .signCount = @intCast(usageCnt),
    };
    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        auth.getAssertion.?.rpId.get(),
        &auth_data.rpIdHash,
        .{},
    );

    const ad = auth_data.encode() catch {
        std.log.err("getNextAssertion: authData encode error", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    // --------------------        ----------------
    // | authenticatorData |      | clientDataHash |
    // --------------------        ----------------
    //         |                          |
    //         ------------------------- | |
    //                                    |
    //         PRIVATE KEY -----------> SIGN
    //                                    |
    //                                    v
    //                           ASSERTION SIGNATURE
    var sig_buffer: [256]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&sig_buffer);
    const allocator = fba.allocator();

    const sig = selected_credential.?.key.sign(
        &.{ ad.get(), &auth.getAssertion.?.cdh },
        allocator,
        .{
            .sig_format = .fido,
        },
    ) catch {
        std.log.err(
            "getAssertion: signature creation failed for credential with id: {x}",
            .{selected_credential.?.id.get()},
        );
        return fido.ctap.StatusCodes.ctap1_err_other;
    };

    const gar = fido.ctap.response.GetAssertion{
        .credential = fido.common.PublicKeyCredentialDescriptor.new(
            selected_credential.?.id.get(),
            .@"public-key",
            null,
        ) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        },
        .authData = ad.get(),
        .signature = sig,
        .user = user,
    };

    cbor.stringify(gar, .{}, out) catch {
        std.log.err("getNextAssertion: cbor encoding error", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    return .ctap1_err_success;
}
