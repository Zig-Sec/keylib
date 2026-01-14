const std = @import("std");
const cbor = @import("zbor");
const cks = @import("cks");
const fido = @import("../../../main.zig");
const helper = @import("helper.zig");

pub fn authenticatorGetAssertion(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.Io.Writer,
) fido.ctap.StatusCodes {
    const di = cbor.DataItem.new(request) catch {
        return .ctap2_err_invalid_cbor;
    };
    const gap = cbor.parse(fido.ctap.request.GetAssertion, di, .{}) catch {
        std.log.err("unable to map request to `GetAssertion` data type", .{});
        return .ctap2_err_invalid_cbor;
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 1. and 2. Verify pinUvAuthParam
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const status = helper.verifyPinUvAuthParam(auth, gap);
    if (status != .ctap1_err_success) return status;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 3. we'll create the response struct later on!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var uv_response = false;
    var up_response = false;

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 4. Validate options
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const uv_supported = auth.uvSupported();

    var uv = gap.requestsUv();
    uv = if (gap.pinUvAuthParam != null) false else uv; // pin overwrites uv
    if (uv and !uv_supported) {
        return fido.ctap.StatusCodes.ctap2_err_invalid_option;
    }

    const rk = gap.requestsRk();
    if (rk) {
        return fido.ctap.StatusCodes.ctap2_err_unsupported_option;
    }

    const up = gap.requestsUp();

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 5. Validate alwaysUv
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    const alwaysUv = auth.alwaysUv() catch {
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    const noMcGaPermissionsWithClientPin = auth.noMcGaPermissionsWithClientPin();

    if (alwaysUv and up) blk: {
        const is_protected = auth.isProtected();

        if (!is_protected) {
            std.log.err("getAssertion: alwaysUv = true but not protected", .{});
            // This handles the case that clientPin is supported in general
            // but not configured yet.
            if (auth.clientPinSupported()) |_| {
                if (!noMcGaPermissionsWithClientPin) {
                    return fido.ctap.StatusCodes.ctap2_err_pin_required;
                }
            } else {
                return fido.ctap.StatusCodes.ctap2_err_operation_denied;
            }
        }

        if (gap.pinUvAuthParam != null) {
            // Go to step 6
            break :blk;
        }

        if (uv) {
            // Go to step 6
            break :blk;
        }

        if (!uv and uv_supported) {
            uv = true;
            break :blk;
        }

        if (auth.clientPinSupported() != null and !noMcGaPermissionsWithClientPin) {
            return fido.ctap.StatusCodes.ctap2_err_pin_required;
        }

        // Else: clientPin is not supported
        return fido.ctap.StatusCodes.ctap2_err_operation_denied;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Validate enterpriseAttestation
    //
    // WE ARE CURRENTLY NOT ENTERPRISE ATTESTATION CAPABLE!
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (gap.enterpriseAttestation) |ea| {
        std.log.err("getAssertion: enterprise attestation not supported", .{});
        _ = ea;
        return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 6. Verify user
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (auth.isProtected()) {
        if (gap.pinUvAuthParam) |puap| {
            if (!auth.token.verify_token(&gap.clientDataHash, puap.get())) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.permissions & 0x02 == 0) {
                // Check if ga permission is set
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            if (auth.token.rp_id) |rp_id| {
                // Match rpIds if possible
                if (!std.mem.eql(u8, gap.rpId.get(), rp_id.get())) {
                    // Ids don't match
                    return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
                }
            }

            if (!auth.token.getUserVerifiedFlagValue()) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            } else {
                uv_response = true;
            }

            // associate the rpId with the token
            if (auth.token.rp_id == null) {
                auth.token.setRpId(gap.rpId.get()) catch {
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }
        } else if (uv) {
            const uvState = auth.token.performBuiltInUv(
                true,
                auth,
                "Get Assertion",
                null,
                .{ .id = gap.rpId },
            );
            switch (uvState) {
                .Blocked => return fido.ctap.StatusCodes.ctap2_err_pin_blocked,
                .Timeout => return fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
                .Denied => {
                    if (auth.clientPinSupported()) |supported| {
                        if (supported and !noMcGaPermissionsWithClientPin) {
                            return fido.ctap.StatusCodes.ctap2_err_pin_required;
                        }
                    }
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                },
                .Accepted => {
                    uv_response = true;
                },
                .AcceptedWithUp => {
                    uv_response = true;
                    up_response = true;
                },
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 8. Locate credentials
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var selected_credential: ?fido.ctap.authenticator.Credential = null;
    var total_credentials: usize = 0;
    var credential = auth.callbacks.read_first(null, gap.rpId, null) catch {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    };

    while (true) {
        var skip = false;
        const policy = credential.policy;

        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (policy == .userVerificationRequired and !uv_response) {
            skip = true;
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (policy == .userVerificationOptionalWithCredentialIDList and gap.allowList == null and !uv_response) {
            skip = true;
        }

        // TODO: check allow list

        if (!skip) {
            total_credentials += 1;
            if (selected_credential == null) {
                selected_credential = credential;
            }
        }

        credential = auth.callbacks.read_next() catch {
            break;
        };
    }

    // We previously iterated over all credentials, now we have to get back to the
    // first one, so we can iterate over the remaining ones using getNextAssertion.
    credential = auth.callbacks.read_first(null, gap.rpId, null) catch {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    };

    while (true) {
        var skip = false;
        const policy = credential.policy;

        // if credential protection for a credential is marked as
        // userVerificationRequired, and the "uv" bit is false in
        // the response, remove that credential from the applicable
        // credentials list
        if (policy == .userVerificationRequired and !uv_response) {
            skip = true;
        }

        // if credential protection for a credential is marked as
        // userVerificationOptionalWithCredentialIDList and there
        // is no allowList passed by the client and the "uv" bit is
        // false in the response, remove that credential from the
        // applicable credentials list
        if (policy == .userVerificationOptionalWithCredentialIDList and gap.allowList == null and !uv_response) {
            skip = true;
        }

        // TODO: check allow list

        if (!skip) {
            break;
        }

        credential = auth.callbacks.read_next() catch {
            break;
        };
    }

    if (selected_credential == null) {
        return fido.ctap.StatusCodes.ctap2_err_no_credentials;
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 10. Check user presence
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    if (up and !up_response) {
        if (gap.pinUvAuthParam != null) {
            if (!auth.token.getUserPresentFlagValue()) {
                if (auth.callbacks.up(
                    "Authentication: Verification Failed",
                    null,
                    .{ .id = gap.rpId },
                ) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        } else {
            if (!up_response) {
                if (auth.callbacks.up(
                    "Authentication: Verification Failed",
                    null,
                    .{ .id = gap.rpId },
                ) != .Accepted) {
                    return fido.ctap.StatusCodes.ctap2_err_operation_denied;
                }
            }
        }

        up_response = true;

        auth.token.clearUserPresentFlag();
        auth.token.clearUserVerifiedFlag();
        auth.token.clearPinUvAuthTokenPermissionsExceptLbw();
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 10. Process extensions
    // ++++++++++++++++++++++++++++++++++++++++++++++++

    var @"hmac-secret": ?fido.common.dt.ABS64B = null;
    if (gap.extensions) |extensions| {
        if (extensions.@"hmac-secret") |hms| {
            switch (hms) {
                .get => |hmsget| {
                    var stat: fido.ctap.StatusCodes = .ctap1_err_success;

                    @"hmac-secret" = hmsget.generate(
                        &stat,
                        auth,
                        &selected_credential.?,
                        uv_response,
                    );

                    if (stat != .ctap1_err_success) {
                        return stat;
                    }
                },
                else => {},
            }
        }
    }

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 11. + 12. Finally select credential
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // Fuck sorting the credentials ...
    // ... credential has already been selected

    var write_back: bool = false;
    if (!auth.constSignCount) {
        selected_credential.?.sign_count += 1;
        write_back = true;
    }
    const usageCnt = selected_credential.?.sign_count;

    const user = if (uv_response) blk: {
        // User identifiable information (name, DisplayName, icon)
        // inside the publicKeyCredentialUserEntity MUST NOT be returned
        // if user verification is not done by the authenticator
        break :blk selected_credential.?.user;
    } else blk: {
        break :blk fido.common.User{ .id = selected_credential.?.user.id };
    };

    // ++++++++++++++++++++++++++++++++++++++++++++++++
    // 13. Sign data
    // ++++++++++++++++++++++++++++++++++++++++++++++++
    var auth_data = fido.common.AuthenticatorData{
        .rpIdHash = undefined,
        .flags = .{
            .up = if (up_response) 1 else 0,
            .rfu1 = 0,
            .uv = if (uv_response) 1 else 0,
            .rfu2 = 0,
            .at = 0,
            .ed = 0,
        },
        .signCount = @intCast(usageCnt),
    };

    if (@"hmac-secret") |hms| {
        auth_data.extensions = .{
            .@"hmac-secret" = .{ .output = hms },
        };
    }

    std.crypto.hash.sha2.Sha256.hash( // calculate rpId hash
        gap.rpId.get(),
        &auth_data.rpIdHash,
        .{},
    );

    const ad = auth_data.encode() catch {
        std.log.err("getAssertion: authData encode error", .{});
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
        &.{ ad.get(), &gap.clientDataHash },
        allocator,
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
        .numberOfCredentials = total_credentials,
    };

    if (total_credentials > 1) {
        // This is important for authenticatorGetNextAssertion
        auth.getAssertion = .{
            .ts = auth.milliTimestamp(),
            .total = total_credentials,
            .count = 1,
            .up = up_response,
            .uv = uv_response,
            .allowList = gap.allowList,
            .rpId = gap.rpId,
            .cdh = gap.clientDataHash,
        };
    }

    if (write_back) {
        // If the sign count is not updated we don't need to update the
        // credentials DB entry, i.e. shared resident keys (passkeys)
        // are not at risk getting out of sync.
        auth.callbacks.write(selected_credential.?) catch {
            std.log.err("getAssertion: unable to update credential", .{});
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    cbor.stringify(gar, .{}, out) catch {
        std.log.err("getAssertion: cbor encoding error", .{});
        return fido.ctap.StatusCodes.ctap1_err_other;
    };
    return status;
}
