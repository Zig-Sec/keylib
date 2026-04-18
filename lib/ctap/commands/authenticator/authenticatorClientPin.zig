const std = @import("std");
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const cbor = @import("zbor");
const fido = @import("../../../main.zig");
const dt = fido.common.dt;

pub fn authenticatorClientPin(
    auth: *fido.ctap.authenticator.Auth,
    request: []const u8,
    out: *std.Io.Writer,
) fido.ctap.StatusCodes {
    const retry_state = struct {
        threadlocal var ctr: u8 = 3;
        threadlocal var powerCycleState: bool = false;
    };

    const client_pin_param = cbor.parse(
        fido.ctap.request.ClientPin,
        cbor.DataItem.new(request) catch {
            return .ctap2_err_invalid_cbor;
        },
        .{},
    ) catch {
        return .ctap2_err_invalid_cbor;
    };

    var client_pin_response: ?fido.ctap.response.ClientPin = null;

    // Handle one of the sub-commands
    switch (client_pin_param.subCommand) {
        .getPinRetries => {
            const settings = auth.callbacks.read_settings();

            client_pin_response = .{
                .pinRetries = settings.pinRetries,
                .powerCycleState = retry_state.powerCycleState,
            };
        },
        .getUVRetries => {
            const settings = auth.callbacks.read_settings();

            client_pin_response = .{
                .uvRetries = settings.uvRetries,
            };
        },
        .getKeyAgreement => {
            const protocol = if (client_pin_param.pinUvAuthProtocol) |prot| prot else {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            };

            // return error if authenticator doesn't support the selected protocol.
            if (protocol != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            client_pin_response = .{
                .keyAgreement = auth.token.getPublicKey(),
            };
        },
        .changePIN => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

            // 1. If the authenticator does not receive mandatory parameters for this
            // command, it returns CTAP2_ERR_MISSING_PARAMETER error.
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.newPinEnc == null or
                client_pin_param.pinUvAuthParam == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            // 2. If pinUvAuthProtocol is not supported, return CTAP1_ERR_INVALID_PARAMETER.
            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // 3. If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            var settings = auth.callbacks.read_settings();

            if (settings.pinRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // 4. The authenticator calls decapsulate on the provided platform
            // key-agreement key to obtain the shared secret. If an error
            // results, it returns CTAP1_ERR_INVALID_PARAMETER.
            const shared_secret = auth.token.ecdh(client_pin_param.keyAgreement.?) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // 5. The authenticator calls
            // verify(shared secret, newPinEnc || pinHashEnc, pinUvAuthParam)
            const newPinEnc = client_pin_param.newPinEnc.?.get();
            const pinHashEnc = client_pin_param.pinHashEnc.?.get();

            var buffer: [256]u8 = .{0} ** 256;
            const len = newPinEnc.len + pinHashEnc.len;
            @memcpy(buffer[0..newPinEnc.len], newPinEnc);
            @memcpy(buffer[newPinEnc.len..len], pinHashEnc);

            if (!auth.token.verify(
                shared_secret.get(),
                buffer[0..len],
                client_pin_param.pinUvAuthParam.?.get(),
            )) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_invalid;
            }

            // 6. Authenticator decrements the pinRetries counter by 1.
            settings.pinRetries -= 1;
            auth.callbacks.write_settings(settings);

            // 7. Authenticator decrypts pinHashEnc
            // using decrypt(shared secret, pinHashEnc) and verifies against its
            // internal stored LEFT(SHA-256(curPin), 16).
            var pinHash: [16]u8 = .{0} ** 16; // LEFT(SHA-256(newPin), 16)
            auth.token.decrypt(
                shared_secret.get(),
                &pinHash,
                pinHashEnc,
            );

            const authenticated = auth.callbacks.uv.?(
                "Change PIN",
                null,
                null,
                &pinHash,
            );
            switch (authenticated) {
                .Denied, .Timeout => {
                    auth.token.regenerate();

                    if (settings.pinRetries == 0) {
                        return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                    }

                    // TODO check 3 consecutive retires to mitigate
                    // DOS attacks

                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                },
                .AcceptedWithUp => {},
                .Accepted => {},
            }

            // 8. Authenticator sets the pinRetries counter to maximum value.
            settings.uvRetries = 8;
            auth.callbacks.write_settings(settings);

            // 9. The authenticator calls decrypt(shared secret, newPinEnc) to
            // produce paddedNewPin. If an error results, it returns
            // CTAP2_ERR_PIN_AUTH_INVALID.

            // It is important to check that we initialize the
            // buffer with something other than 0 because the
            // last byte of the padded pin is 0 and we want to
            // make sure that it is actually null terminated.
            var paddedNewPin: [64]u8 = .{'a'} ** 64;
            auth.token.decrypt(
                shared_secret.get(),
                &paddedNewPin,
                newPinEnc,
            );

            if (paddedNewPin[63] != 0) {
                return .ctap2_err_pin_auth_invalid;
            }

            var i: usize = 63;
            while (i > 0 and paddedNewPin[i - 1] == 0) i -= 1;

            const newPin = paddedNewPin[0..i];

            if (newPin.len < settings.min_pin_length) {
                return .ctap2_err_pin_policy_violation;
            }

            // 13. If the forcePINChange member of the authenticatorGetInfo response
            // is true and LEFT(SHA-256(newPin), 16) is equal to its internal stored
            // LEFT(SHA-256(curPin), 16) then authenticator returns
            // CTAP2_ERR_PIN_POLICY_VIOLATION.

            // TODO: implement force pin change check

            settings.force_pin_change = false;
            auth.callbacks.write_settings(settings);

            // 17. Authenticator stores LEFT(SHA-256(newPin), 16) internally as the new
            // value of CurrentStoredPIN.

            var digest: [32]u8 = .{0} ** 32;
            std.crypto.hash.sha2.Sha256.hash(newPin, &digest, .{});

            auth.callbacks.set_pin.?(digest[0..16]) catch |e| {
                std.log.err("changePin: unable to set new pin ({any})", .{e});
                return .ctap1_err_other;
            };

            // 19. Authenticator calls resetPinUvAuthToken() for all pinUvAuthProtocols
            // supported by this authenticator. (I.e. all existing pinUvAuthTokens are
            // invalidated.)
            auth.token.resetPinUvAuthToken();

            // 20. Authenticator calls resetPersistentPinUvAuthToken() (all
            // persistent permissions are cleared on pin change).

            // TODO: when implementing persistent pins.
        },
        .getPinUvAuthTokenUsingUvWithPermissions => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.permissions == null or
                client_pin_param.permissions == null or
                client_pin_param.keyAgreement == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            if (client_pin_param.permissions.? == 0) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Check if all requested premissions are valid
            const options = auth.settings.options;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            // The mc and ga permissions are always considered authorized, thus they are not listed below.
            if (cm or be or lbw or acfg) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            if (!auth.uvSupported()) {
                return fido.ctap.StatusCodes.ctap2_err_not_allowed;
            }

            const settings = auth.callbacks.read_settings();

            if (settings.uvRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_uv_blocked;
            }

            var user_present = false;
            switch (auth.token.performBuiltInUv(
                true,
                auth,
                "User Verification",
                null,
                null,
            )) {
                .Blocked => return fido.ctap.StatusCodes.ctap2_err_uv_blocked,
                .Timeout => return fido.ctap.StatusCodes.ctap2_err_user_action_timeout,
                .Denied => {
                    return fido.ctap.StatusCodes.ctap2_err_uv_invalid;
                },
                .Accepted => {},
                .AcceptedWithUp => user_present = true,
            }

            auth.token.resetPinUvAuthToken(); // invalidates existing tokens
            auth.token.beginUsingPinUvAuthToken(user_present, std.Io.Timestamp.now(auth.io, .real));

            auth.token.permissions = client_pin_param.permissions.?;

            // If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                auth.token.setRpId(rpId.get()) catch {
                    // rpId is unexpectedly long
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }

            // Obtain the shared secret
            const shared_secret = auth.token.ecdh(
                client_pin_param.keyAgreement.?,
            ) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret: [48]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret.get(),
                enc_shared_secret[0..],
                auth.token.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = (dt.ABS48B.fromSlice(&enc_shared_secret) catch unreachable).?,
            };
        },
        .getPinUvAuthTokenUsingPinWithPermissions => {
            if (retry_state.ctr == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_auth_blocked;
            }

            // 1. If the authenticator does not receive mandatory parameters for
            // this command, it returns CTAP2_ERR_MISSING_PARAMETER error.
            if (client_pin_param.pinUvAuthProtocol == null or
                client_pin_param.keyAgreement == null or
                client_pin_param.pinHashEnc == null or
                client_pin_param.permissions == null)
            {
                return fido.ctap.StatusCodes.ctap2_err_missing_parameter;
            }

            // 2. If pinUvAuthProtocol is not supported, return
            // CTAP1_ERR_INVALID_PARAMETER.
            if (client_pin_param.pinUvAuthProtocol.? != auth.token.version) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // 3. If the authenticator receives a permissions parameter with value
            // 0, return CTAP1_ERR_INVALID_PARAMETER.
            if (client_pin_param.permissions.? == 0) {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            }

            // Check if all requested premissions are valid
            const options = auth.settings.options;
            const cm = client_pin_param.cmPermissionSet() and (options.credMgmt == null or options.credMgmt.? == false);
            const be = client_pin_param.bePermissionSet() and (options.bioEnroll == null);
            const lbw = client_pin_param.lbwPermissionSet() and (options.largeBlobs == null or options.largeBlobs.? == false);
            const acfg = client_pin_param.acfgPermissionSet() and (options.authnrCfg == null or options.authnrCfg.? == false);
            // The mc and ga permissions are always considered authorized, thus they are not listed below.
            if (cm or be or lbw or acfg) {
                return fido.ctap.StatusCodes.ctap2_err_unauthorized_permission;
            }

            // 5. If the pinRetries counter is 0, return CTAP2_ERR_PIN_BLOCKED error.
            var settings = auth.callbacks.read_settings();

            if (settings.pinRetries == 0) {
                return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
            }

            // 6. The authenticator calls decapsulate on the provided platform
            // key-agreement key to obtain the shared secret. If an error
            // results, it returns CTAP1_ERR_INVALID_PARAMETER.
            const shared_secret = auth.token.ecdh(client_pin_param.keyAgreement.?) catch {
                return fido.ctap.StatusCodes.ctap1_err_invalid_parameter;
            };

            // 7. might be handeled by the uv callback

            // 8. Authenticator decrements the pinRetries counter by 1.
            settings.pinRetries -= 1;
            auth.callbacks.write_settings(settings);

            // 9. Authenticator decrypts pinHashEnc using decrypt and verifies
            // against its internally stored CurrentStoredPIN.
            var pinHash: [16]u8 = .{0} ** 16; // LEFT(SHA-256(newPin), 16)
            auth.token.decrypt(
                shared_secret.get(),
                &pinHash,
                client_pin_param.pinHashEnc.?.get(),
            );

            const authenticated = auth.callbacks.uv.?(
                "Pin Verification",
                null,
                null,
                &pinHash,
            );
            switch (authenticated) {
                .Denied, .Timeout => {
                    auth.token.regenerate();

                    if (settings.pinRetries == 0) {
                        return fido.ctap.StatusCodes.ctap2_err_pin_blocked;
                    }

                    // TODO check 3 consecutive retires to mitigate
                    // DOS attacks

                    return fido.ctap.StatusCodes.ctap2_err_pin_invalid;
                },
                .AcceptedWithUp => {},
                .Accepted => {},
            }

            // 10. Authenticator sets the pinRetries counter to maximum value.
            settings.uvRetries = 8;
            auth.callbacks.write_settings(settings);

            // 11. If the value of the forcePINChange member of the
            // authenticatorGetInfo response is true, authenticator
            // returns CTAP2_ERR_PIN_POLICY_VIOLATION. Platform on
            // receiving such error response SHOULD direct the user
            // to change the PIN.
            if (settings.force_pin_change == true) {
                return fido.ctap.StatusCodes.ctap2_err_pin_policy_violation;
            }

            // 12. TODO: handle pcmr token

            // 13. Create a new pinUvAuthToken by calling resetPinUvAuthToken()
            // for all pinUvAuthProtocols supported by this authenticator.
            // (I.e. all existing pinUvAuthTokens are invalidated.)
            auth.token.resetPinUvAuthToken(); // invalidates existing tokens

            // 14. Call beginUsingPinUvAuthToken(userIsPresent: false).
            auth.token.beginUsingPinUvAuthToken(
                false,
                std.Io.Timestamp.now(auth.io, .real),
            );

            // 15. Assign the requested permissions to the pinUvAuthToken,
            // ignoring any undefined permissions.
            auth.token.permissions = client_pin_param.permissions.?;

            // 16. If the rpId parameter is present, associate the permissions RP ID
            // with the pinUvAuthToken.
            if (client_pin_param.rpId) |rpId| {
                auth.token.setRpId(rpId.get()) catch {
                    // rpId is unexpectedly long
                    return fido.ctap.StatusCodes.ctap1_err_other;
                };
            }

            // The authenticator returns the encrypted pinUvAuthToken for the
            // specified pinUvAuthProtocol, i.e. encrypt(shared secret, pinUvAuthToken).
            var enc_shared_secret: [48]u8 = undefined;
            auth.token.encrypt(
                &auth.token,
                shared_secret.get(),
                enc_shared_secret[0..],
                auth.token.pin_token[0..],
            );

            // Response
            client_pin_response = .{
                .pinUvAuthToken = (dt.ABS48B.fromSlice(&enc_shared_secret) catch unreachable).?,
            };
        },
        else => {
            return fido.ctap.StatusCodes.ctap2_err_invalid_subcommand;
        },
    }

    // Serialize response and return
    if (client_pin_response) |resp| {
        cbor.stringify(resp, .{}, out) catch {
            return fido.ctap.StatusCodes.ctap1_err_other;
        };
    }

    return fido.ctap.StatusCodes.ctap1_err_success;
}
