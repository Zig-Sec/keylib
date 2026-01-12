const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const Transport = @import("Transport.zig");
const err = @import("error.zig");

/// The Promise represents the eventual completion of a operation.
pub const Promise = struct {
    t: *Transport,
    start: i64,
    timeout: i64,

    pub const StateTag = enum { pending, fulfilled, rejected };
    pub const Pending = enum { processing, user_presence, waiting };
    pub const State = union(StateTag) {
        pending: Pending,
        fulfilled: []const u8,
        rejected: err.StatusCodes,

        pub fn deinit(self: *const @This(), a: std.mem.Allocator) void {
            switch (self.*) {
                .pending => {},
                .rejected => {},
                .fulfilled => |data| {
                    a.free(data);
                },
            }
        }

        pub fn deserializeCbor(self: *const @This(), comptime T: type, a: std.mem.Allocator) !T {
            return switch (self.*) {
                .pending => error.Pending,
                .rejected => error.Rejected,
                .fulfilled => |data| blk: {
                    break :blk try cbor.parse(T, try cbor.DataItem.new(data[1..]), .{ .allocator = a });
                },
            };
        }
    };

    /// Create a new Promise with a timeout in ms.
    pub fn new(t: *Transport, timeout: i64) @This() {
        return .{
            .t = t,
            .start = std.time.milliTimestamp(),
            .timeout = timeout,
        };
    }

    /// Wait until the promise is fulfilled.
    ///
    /// Either returns fulfilled or an error.
    pub fn await(self: *const @This(), allocator: std.mem.Allocator) !State {
        while (true) {
            const S = self.get(allocator);

            switch (S) {
                .pending => {},
                .fulfilled => return S,
                .rejected => |e| return e,
            }
        }
    }

    /// Query the current state of the Promise.
    pub fn get(self: *const @This(), allocator: std.mem.Allocator) State {
        if (std.time.milliTimestamp() - self.start > self.timeout) {
            return .{ .rejected = err.StatusCodes.client_timeout };
            // TODO: should we send a abort message or something???
        }

        const resp = self.t.read(allocator) catch |e| {
            if (e == error.Processing) {
                return .{ .pending = .processing };
            } else if (e == error.UpNeeded) {
                return .{ .pending = .user_presence };
            } else {
                // This is an error we can't handle
                return .{ .rejected = err.StatusCodes.ctap1_err_other };
            }
        };

        if (resp) |response| {
            if (response[0] != 0) {
                defer allocator.free(response);
                return .{ .rejected = err.errorFromInt(response[0]) };
            }

            return .{ .fulfilled = response };
        } else {
            return .{ .pending = .waiting };
        }
    }
};

// ///////////////////////////////////////
// Get Info (0x04)
// ///////////////////////////////////////

/// Information about a FIDO authenticator including:
/// * version (e.g. FIDO_2_1)
/// * pinUvAuthProtocols (none, 1, 2): this is important when requesting a token
/// * options: e.g. rk (supports discoverable credentials, also known as passkeys)
pub const Info = keylib.ctap.authenticator.Settings;

/// Make a authenticatorGetInfo request
pub fn authenticatorGetInfo(t: *Transport) !Promise {
    const cmd = "\x04";
    try t.write(cmd);
    return Promise.new(t, 500);
}

// ///////////////////////////////////////
// Reset (0x07)
// ///////////////////////////////////////

/// Make a authenticatorGetInfo request
pub fn authenticatorReset(t: *Transport, tout: i64) !Promise {
    const cmd = "\x07";
    try t.write(cmd);
    return Promise.new(t, tout);
}

// ///////////////////////////////////////
// Authenticator Selection (0x0b)
// ///////////////////////////////////////

/// Make a authenticatorSelection request.
pub fn authenticatorSelection(t: *Transport, timeout: i64) !Promise {
    const cmd = "\x0b";
    try t.write(cmd);
    return Promise.new(t, timeout);
}

// ///////////////////////////////////////
// pinUvAuthToken
// ///////////////////////////////////////

/// Obtain a pinUvAuthToken
///
/// On success, returns the tuple: `(PinProtocol, token)`
pub fn pinUvAuthToken(
    t: *Transport,
    allocator: std.mem.Allocator,
    info: Info,
    params: struct {
        rpId: ?[]const u8 = null,
        pin: ?[]const u8 = null,
        permissions: client_pin.Permissions = .{},
    },
) !struct { keylib.ctap.pinuv.common.PinProtocol, []const u8 } {
    var token: ?[]const u8 = null;

    if (info.pinUvAuthProtocols == null or info.pinUvAuthProtocols.?.len == 0) {
        return error.PinUvAuthProtocolNotSupportedByAuthenticator;
    }

    // Obtain a shared secret
    const pinUvAuthProtocol = info.pinUvAuthProtocols.?[0];
    var shared_secret = try client_pin.getKeyAgreement(
        t,
        pinUvAuthProtocol,
        allocator,
    );

    // Obtain pinUvAuthToken
    // see: https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#gettingPinUvAuthToken

    //TODO: Maybe add a fallback later on, e.g. try to use a pin if using build in
    // uv fails...

    // The uv option ID is present and set to true
    if (info.options.uv != null and info.options.uv.?) {
        // pinUvAuthToken option ID present and true
        if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
            if (params.permissions.acfg == 1) {
                if (info.options.uvAcfg == null or !info.options.uvAcfg.?) {
                    // When requesting the acfg permission,
                    // getPinUvAuthTokenUsingUvWithPermissions can only be used
                    // if the uvAcfg Option ID is present and true.
                    return error.PinUvAuthTokenUvAcfgOptionMissingOrFalse;
                }
            }

            token = try client_pin.getPinUvAuthTokenUsingUvWithPermissions(
                t,
                &shared_secret,
                params.permissions,
                params.rpId,
                allocator,
            );
        } else { // pinUvAuthToken option ID false or absent
            return error.PinUvAuthTokenOptionNotSupported;
        }
    } else if (info.options.clientPin != null and info.options.clientPin.?) {
        if (params.pin == null) return error.PinUvAuthTokenPinMissing;

        // pinUvAuthToken option ID present and true
        if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
            if (params.permissions.mc == 1 or params.permissions.ga == 1) {
                // When requesting the mc or ga permissions,
                // getPinUvAuthTokenUsingPinWithPermissions can only be used if the
                // noMcGaPermissionsWithClientPin Option ID is absent or set to false.
                if (info.options.noMcGaPermissionsWithClientPin) {
                    return error.PinUvAuthTokenMcGaWithPinNotAllowed;
                }
            }

            token = try client_pin.getPinUvAuthTokenUsingPinWithPermissions(
                t,
                &shared_secret,
                params.permissions,
                params.rpId,
                params.pin.?, // we have already checked that the pin is present
                allocator,
            );
        } else { // the pinUvAuthToken option ID is absent
            token = try client_pin.getPinToken(
                t,
                &shared_secret,
                params.pin.?, // we have already checked that pin is present
                allocator,
            );
        }
    } else {
        return error.PinUvAuthTokenOptionNotSupported;
    }

    if (token) |tok| {
        return .{ pinUvAuthProtocol, tok };
    } else {
        return error.PinUvAuthTokenCreationFailed;
    }
}

// ///////////////////////////////////////
// Credential
// ///////////////////////////////////////

pub const credentials = struct {
    pub const PublicKey = struct {
        // https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create#publickey_object_structure

        pub const Attestation = enum {
            none,
            direct,
            enterprise,
            indirect,
        };

        pub const Attachment = enum {
            platform,
            @"cross-platform",
        };

        pub const Requirements = enum {
            discouraged,
            preferred,
            required,
        };

        pub const Transports = enum {
            ble,
            hybrid,
            internal,
            nfc,
            usb,
        };

        pub const Hints = enum {
            @"security-key",
            @"client-device",
            hybrid,
        };

        attestation: ?[]const u8 = null,
        attestationFormats: ?[]const keylib.common.AttestationStatementFormatIdentifiers = null,
        authenticatorSelection: ?struct {
            authenticatorAttachment: ?Attachment = null,
            requireResidentKey: ?bool = null,
            residentKey: ?Requirements = null,
            userVerification: ?Requirements = null,
        } = null,
        challenge: []const u8,
        excludeCredentials: ?[]const keylib.common.PublicKeyCredentialDescriptor = null,
        allowCredentials: ?[]const keylib.common.PublicKeyCredentialDescriptor = null,
        pubKeyCredParams: ?[]const keylib.common.PublicKeyCredentialParameters = null,
        rp: ?keylib.common.RelyingParty = null,
        rpId: ?[]const u8 = null,
        /// The time in ms the rp is willing to wait
        timeout: i64 = 300000,
        user: ?keylib.common.User = null,
        hints: ?[]const Hints = null,
        userVerification: ?Requirements = null,
    };

    pub const Options = struct {
        protocol: ?keylib.ctap.pinuv.common.PinProtocol = null,
        param: ?[]const u8 = null,
    };

    /// Create a client data hash
    ///
    /// ## Arguments
    ///
    /// - `typ`: "webauthn.create" / "webauthn.get"
    /// - `challenge`: a challenge (nonce)
    /// - `origin`: an origin (e.g. localhost)
    /// - `corssOrigin`
    pub fn clientDataHash(
        a: std.mem.Allocator,
        typ: []const u8,
        challenge: []const u8,
        origin: []const u8,
        crossOrigin: bool,
    ) ![Sha256.digest_length]u8 {
        // The challenge is base64 encoded before being integrated into the client data
        const Base64 = std.base64.url_safe.Encoder;
        const c = try a.alloc(u8, Base64.calcSize(challenge.len));
        defer a.free(c);
        _ = Base64.encode(c, challenge);

        // Serialize the client data and then hash them...
        const client_data = try serialize(
            a,
            typ,
            c,
            origin,
            crossOrigin,
        );
        defer a.free(client_data);
        var client_data_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(client_data, client_data_hash[0..], .{});

        return client_data_hash;
    }

    pub const MakeCredentialResponse = keylib.ctap.response.MakeCredential;
    pub const GetAssertionResponse = keylib.ctap.response.GetAssertion;

    /// Create a new credential using the authenticatorMakeCredential command.
    ///
    /// This function enforces user verification, either using builtin uv
    /// or a pin. Creating a credential without user verification is not
    /// supported.
    pub fn create(
        t: *Transport,
        token: []const u8,
        pinUvAuthProtocol: keylib.ctap.pinuv.common.PinProtocol,
        allocator: std.mem.Allocator,
        params: struct {
            rpId: []const u8,
            userId: []const u8,
            challenge: []const u8,
            rpName: ?[]const u8 = null,
            crossOrigin: bool = false,
            userName: ?[]const u8 = null,
            userDisplayName: ?[]const u8 = null,
            rk: ?bool = null,
            uv: bool = false,
            hms: bool = false,
            type: keylib.common.PublicKeyCredentialParameters = .{
                .alg = .Es256,
                .type = .@"public-key",
            },
            timeout: i64 = 30000,
        },
    ) !Promise {
        // ===========================
        // Create client data hash
        // ===========================

        const client_data_hash = try credentials.clientDataHash(
            allocator,
            "webauthn.create",
            params.challenge,
            params.rpId,
            params.crossOrigin,
        );

        // ===========================
        // Prepare data
        // ===========================

        const rp = try keylib.common.RelyingParty.new(
            params.rpId,
            params.rpName,
        );

        const user = try keylib.common.User.new(
            params.userId,
            params.userName,
            params.userDisplayName,
        );

        var mc = keylib.ctap.request.MakeCredential{
            .clientDataHash = client_data_hash,
            .rp = rp,
            .user = user,
            .pubKeyCredParams = (try keylib.common.dt.ABSPublicKeyCredentialParameters.fromSlice(&.{params.type})).?,
            .options = .{
                .rk = params.rk,
                .up = null,
                .uv = null, // uv must not be set when using pinUvAuthParam
            },
        };

        mc.pinUvAuthParam = switch (pinUvAuthProtocol) {
            .V1 => PinUvAuth.authenticate_v1(
                token,
                &client_data_hash,
            ),
            .V2 => PinUvAuth.authenticate_v2(
                token,
                &client_data_hash,
            ),
        };
        mc.pinUvAuthProtocol = pinUvAuthProtocol;

        // ===========================
        // Sending request
        // ===========================

        var arr = std.Io.Writer.Allocating.init(allocator);
        defer arr.deinit();

        try arr.writer.writeByte(0x01);
        try cbor.stringify(mc, .{}, &arr.writer);

        //std.debug.print("{x}\n", .{arr.written()});

        try t.write(arr.written());

        return Promise.new(t, params.timeout);
    }

    pub fn getAssertion(
        t: *Transport,
        token: []const u8,
        pinUvAuthProtocol: keylib.ctap.pinuv.common.PinProtocol,
        allocator: std.mem.Allocator,
        params: struct {
            rpId: []const u8,
            challenge: []const u8,
            crossOrigin: bool = false,
            hms: bool = false,
            // TODO: add allow list
            timeout: i64 = 30000,
        },
    ) !struct { Promise, [Sha256.digest_length]u8 } {
        // ===========================
        // Create client data hash
        // ===========================

        const client_data_hash = try credentials.clientDataHash(
            allocator,
            "webauthn.get",
            params.challenge,
            params.rpId,
            params.crossOrigin,
        );

        // ===========================
        // Prepare data
        // ===========================

        var ga = keylib.ctap.request.GetAssertion{
            .rpId = (try keylib.common.dt.ABS128T.fromSlice(params.rpId)).?,
            .clientDataHash = client_data_hash,
            .options = .{
                .up = null,
                .uv = null, // uv must not be set when using pinUvAuthParam
            },
        };

        ga.pinUvAuthParam = switch (pinUvAuthProtocol) {
            .V1 => PinUvAuth.authenticate_v1(
                token,
                &client_data_hash,
            ),
            .V2 => PinUvAuth.authenticate_v2(
                token,
                &client_data_hash,
            ),
        };
        ga.pinUvAuthProtocol = pinUvAuthProtocol;

        // ===========================
        // Sending request
        // ===========================

        var arr = std.Io.Writer.Allocating.init(allocator);
        defer arr.deinit();

        try arr.writer.writeByte(0x02);
        try cbor.stringify(ga, .{}, &arr.writer);

        //std.debug.print("{x}\n", .{arr.written()});

        try t.write(arr.written());

        return .{ Promise.new(t, params.timeout), client_data_hash };
    }

    pub fn getNextAssertion(
        t: *Transport,
        allocator: std.mem.Allocator,
        params: struct {
            timeout: i64 = 30000,
        },
    ) !Promise {
        // ===========================
        // Sending request
        // ===========================

        var arr = std.Io.Writer.Allocating.init(allocator);
        defer arr.deinit();

        try arr.writer.writeByte(0x08);

        //std.debug.print("{x}\n", .{arr.written()});

        try t.write(arr.written());

        return Promise.new(t, params.timeout);
    }

    /// Serialize the collected client data.
    ///
    /// Also see: [WebAuthn](https://www.w3.org/TR/webauthn/#clientdatajson-serialization)
    pub fn serialize(
        a: std.mem.Allocator,
        typ: []const u8,
        challenge: []const u8,
        origin: []const u8,
        crossOrigin: bool,
    ) ![]const u8 {
        var out = std.Io.Writer.Allocating.init(a);
        errdefer out.deinit();

        try out.writer.writeAll("{\"type\":");
        try CCDToString(&out.writer, typ);
        try out.writer.writeAll(",\"challenge\":");
        try CCDToString(&out.writer, challenge);
        try out.writer.writeAll(",\"origin\":");
        try CCDToString(&out.writer, origin);
        try out.writer.writeAll(",\"crossOrigin\":");
        try out.writer.writeAll(if (crossOrigin) "true" else "false");
        // TODO: handle tokenBinding
        try out.writer.writeAll("}");

        return try out.toOwnedSlice();
    }

    // https://www.w3.org/TR/webauthn-2/#ccdtostring
    pub fn CCDToString(out: *std.Io.Writer, in: []const u8) !void {
        var i: usize = 0;

        //std.log.info("{s}", .{in});

        try out.writeByte(0x22);
        while (i < in.len) : (i += 1) {
            const l = try std.unicode.utf8ByteSequenceLength(in[i]);
            const cp = try std.unicode.utf8Decode(in[i .. i + l]);

            switch (cp) {
                0x20, 0x21, 0x23...0x5b, 0x5d...0x10ffff => try out.writeAll(in[i .. i + l]),
                0x22 => try out.writeAll(&.{ 0x5c, 0x22 }),
                0x5c => try out.writeAll(&.{ 0x5c, 0x5c }),
                else => {
                    var tmp: [4]u8 = .{0} ** 4;
                    @memcpy(tmp[0..l], in[i .. i + l]);
                    try out.writeAll(&.{ 0x5c, 0x75 });
                    try out.print("{x:2}{x:2}{x:2}{x:2}", .{ tmp[3], tmp[2], tmp[1], tmp[0] });
                },
            }
        }
        //for (in) |c| {
        //    switch (c) { // this is not quite correct... TODO: fix this for utf8
        //        0x20, 0x21, 0x23...0x5b, 0x5d...0x7e => try out.writeByte(c),
        //        0x22 => try out.writeAll(&.{ 0x5c, 0x22 }),
        //        0x5c => try out.writeAll(&.{ 0x5c, 0x5c }),
        //        else => {
        //            return error.you_fell_into_my_trap;
        //        },
        //    }
        //}
        try out.writeByte(0x22);
    }
};

// ///////////////////////////////////////
// Client Pin
// ///////////////////////////////////////

pub const PinUvAuth = keylib.ctap.pinuv.PinUvAuth;
pub const ClientPin = keylib.ctap.request.ClientPin;
pub const ClientPinResponse = keylib.ctap.response.ClientPin;
pub const EcdhP256 = keylib.ctap.crypto.dh.EcdhP256;
pub const Sha256 = std.crypto.hash.sha2.Sha256;

pub const client_pin = struct {
    pub const Encapsulation = struct {
        version: keylib.ctap.pinuv.common.PinProtocol,
        platform_key_agreement_key: keylib.ctap.crypto.dh.EcdhP256.KeyPair,
        shared_secret: keylib.common.dt.ABS64B = undefined,
    };

    pub fn encapsulate(
        version: keylib.ctap.pinuv.common.PinProtocol,
        peer_cose_key: cbor.cose.Key,
    ) !Encapsulation {
        var seed: [EcdhP256.secret_length]u8 = undefined;
        std.crypto.random.bytes(seed[0..]);
        const k = try EcdhP256.KeyPair.create(seed);

        const shared_point = try EcdhP256.scalarmultXY(
            k.secret_key,
            peer_cose_key.P256.x,
            peer_cose_key.P256.y,
        );

        const z: [32]u8 = shared_point.toUncompressedSec1()[1..33].*;

        const ss = switch (version) {
            .V1 => PinUvAuth.kdf_v1(z),
            .V2 => PinUvAuth.kdf_v2(z),
        };

        return .{
            .version = version,
            .platform_key_agreement_key = k,
            .shared_secret = ss,
        };
    }

    pub fn getKeyAgreement(
        t: *Transport,
        version: keylib.ctap.pinuv.common.PinProtocol,
        a: std.mem.Allocator,
    ) !Encapsulation {
        const cmd = 0x06;
        const request = ClientPin{
            .pinUvAuthProtocol = version,
            .subCommand = .getKeyAgreement,
        };

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            const cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{});

            if (cpr.keyAgreement == null) return error.MissingPar;

            return try encapsulate(version, cpr.keyAgreement.?);
        } else {
            return error.MissingResponse;
        }
    }

    pub const Permissions = packed struct {
        mc: u1 = 0,
        ga: u1 = 0,
        cm: u1 = 0,
        be: u1 = 0,
        lbw: u1 = 0,
        acfg: u1 = 0,
        reserved1: u1 = 0,
        reserved2: u1 = 0,
    };

    /// Set a PIN for an authenticator.
    ///
    /// The caller is responsible for checking if the new
    /// PIN adheres to the minPINLength set by the authenticator.
    pub fn setPin(
        t: *Transport,
        e: *Encapsulation, // shared secret
        newPin: []const u8,
        a: std.mem.Allocator,
    ) !Promise {
        // 63 bytes is the limit for pins
        if (newPin.len > 63) return error.pin;

        // Platform sends authenticatorClientPIN command to the
        // authenticator.
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .setPIN,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
        };

        var paddedPin: [64]u8 = .{0} ** 64;
        @memcpy(paddedPin[0..newPin.len], newPin);

        var _newPinEnc: [80]u8 = undefined;
        switch (e.version) {
            .V1 => {
                // Encrypt PIN hash
                const iv: [16]u8 = .{0} ** 16;

                // Encrypt padded PIN
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret.get()[0..32].*,
                    _newPinEnc[0..64],
                    &paddedPin,
                );
                request.newPinEnc = try keylib.common.dt.ABS80B.fromSlice(
                    _newPinEnc[0..64],
                );
            },
            .V2 => {
                // Encrypt padded PIN
                std.crypto.random.bytes(_newPinEnc[0..16]);
                PinUvAuth._encrypt(
                    _newPinEnc[0..16].*,
                    e.shared_secret.get()[32..64].*,
                    _newPinEnc[16..80],
                    &paddedPin,
                );
                request.newPinEnc = try keylib.common.dt.ABS80B.fromSlice(
                    _newPinEnc[0..80],
                );
            },
        }

        const param = switch (e.version) {
            .V1 => PinUvAuth.authenticate_v1(e.shared_secret.get(), request.newPinEnc.?.get()),
            .V2 => PinUvAuth.authenticate_v2(e.shared_secret.get(), request.newPinEnc.?.get()),
        };
        request.pinUvAuthParam = param;

        // Serialize request
        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        return Promise.new(t, 500);
    }

    /// Change an existing PIN for an authenticator.
    ///
    /// The caller is responsible for checking if the new
    /// PIN adheres to the minPINLength set by the authenticator.
    pub fn changePin(
        t: *Transport,
        e: *Encapsulation, // shared secret
        curPin: []const u8,
        newPin: []const u8,
        a: std.mem.Allocator,
    ) !Promise {
        // 63 bytes is the limit for pins
        if (curPin.len > 63) return error.pin;
        if (newPin.len > 63) return error.pin;

        // Platform sends authenticatorClientPIN command to the
        // authenticator.
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .changePIN,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
        };

        // Calculate: pinHashEnc: The result of calling
        //            encrypt(shared secret, LEFT(SHA-256(curPin), 16))
        var pin_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(curPin, &pin_hash, .{});
        // Who the fuck would just use half of an hash!?!
        const pin_hash_left = pin_hash[0..16];

        var paddedPin: [64]u8 = .{0} ** 64;
        @memcpy(paddedPin[0..newPin.len], newPin);

        var @"newPinEnc || pinHashEnc": std.ArrayListUnmanaged(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, @"newPinEnc || pinHashEnc".items);
            @"newPinEnc || pinHashEnc".deinit(a);
        }

        var _pinHashEnc: [32]u8 = undefined;
        var _newPinEnc: [80]u8 = undefined;
        switch (e.version) {
            .V1 => {
                // Encrypt PIN hash
                const iv: [16]u8 = .{0} ** 16;
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret.get()[0..32].*,
                    _pinHashEnc[0..16],
                    pin_hash_left,
                );
                request.pinHashEnc = try keylib.common.dt.ABS32B.fromSlice(
                    _pinHashEnc[0..16],
                );

                // Encrypt padded PIN
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret.get()[0..32].*,
                    _newPinEnc[0..64],
                    &paddedPin,
                );
                request.newPinEnc = try keylib.common.dt.ABS80B.fromSlice(
                    _newPinEnc[0..64],
                );

                try @"newPinEnc || pinHashEnc".appendSlice(a, _newPinEnc[0..64]);
                try @"newPinEnc || pinHashEnc".appendSlice(a, _pinHashEnc[0..16]);
            },
            .V2 => {
                // Encrypt PIN hash
                std.crypto.random.bytes(_pinHashEnc[0..16]);
                PinUvAuth._encrypt(
                    _pinHashEnc[0..16].*,
                    e.shared_secret.get()[32..64].*,
                    _pinHashEnc[16..32],
                    pin_hash_left,
                );
                request.pinHashEnc = try keylib.common.dt.ABS32B.fromSlice(
                    _pinHashEnc[0..32],
                );

                // Encrypt padded PIN
                std.crypto.random.bytes(_newPinEnc[0..16]);
                PinUvAuth._encrypt(
                    _newPinEnc[0..16].*,
                    e.shared_secret.get()[32..64].*,
                    _newPinEnc[16..80],
                    &paddedPin,
                );
                request.newPinEnc = try keylib.common.dt.ABS80B.fromSlice(
                    _newPinEnc[0..80],
                );

                try @"newPinEnc || pinHashEnc".appendSlice(a, _newPinEnc[0..80]);
                try @"newPinEnc || pinHashEnc".appendSlice(a, _pinHashEnc[0..32]);
            },
        }

        const param = switch (e.version) {
            .V1 => PinUvAuth.authenticate_v1(e.shared_secret.get(), @"newPinEnc || pinHashEnc".items),
            .V2 => PinUvAuth.authenticate_v2(e.shared_secret.get(), @"newPinEnc || pinHashEnc".items),
        };
        request.pinUvAuthParam = param;

        // Serialize request
        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        return Promise.new(t, 500);
    }

    pub fn getPinToken(
        t: *Transport,
        e: *Encapsulation,
        pin: []const u8,
        a: std.mem.Allocator,
    ) ![]const u8 {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .getPinToken,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
        };

        var pin_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(pin, &pin_hash, .{});
        const pin_hash_left = pin_hash[0..16];

        var _pinHashEnc: [32]u8 = undefined;
        var pinHashEnc: []u8 = undefined;
        switch (e.version) {
            .V1 => {
                const iv: [16]u8 = .{0} ** 16;
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret.get()[0..32].*,
                    _pinHashEnc[0..16],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..16];
            },
            .V2 => {
                std.crypto.random.bytes(_pinHashEnc[0..16]);
                PinUvAuth._encrypt(
                    _pinHashEnc[0..16].*,
                    e.shared_secret.get()[32..64].*,
                    _pinHashEnc[16..32],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..32];
            },
        }
        request.pinHashEnc = try keylib.common.dt.ABS32B.fromSlice(pinHashEnc);

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            const cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{});

            if (cpr.pinUvAuthToken == null) return error.MissingPar;

            var token: []u8 = undefined;
            switch (e.version) {
                .V1 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len);
                    PinUvAuth.decrypt_v1(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
                .V2 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len - 16);
                    PinUvAuth.decrypt_v2(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
            }
            return token;
        } else {
            return error.MissingResponse;
        }
    }

    pub fn getPinUvAuthTokenUsingPinWithPermissions(
        t: *Transport,
        e: *Encapsulation,
        permissions: Permissions,
        rpId: ?[]const u8,
        pin: []const u8,
        a: std.mem.Allocator,
    ) ![]const u8 {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .getPinUvAuthTokenUsingPinWithPermissions,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
            .permissions = std.mem.toBytes(permissions)[0],
        };

        if (rpId) |id| {
            request.rpId = try .fromSlice(id);
        }

        var pin_hash: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(pin, &pin_hash, .{});
        const pin_hash_left = pin_hash[0..16];

        var _pinHashEnc: [32]u8 = undefined;
        var pinHashEnc: []u8 = undefined;
        switch (e.version) {
            .V1 => {
                const iv: [16]u8 = .{0} ** 16;
                PinUvAuth._encrypt(
                    iv,
                    e.shared_secret.get()[0..32].*,
                    _pinHashEnc[0..16],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..16];
            },
            .V2 => {
                std.crypto.random.bytes(_pinHashEnc[0..16]);
                PinUvAuth._encrypt(
                    _pinHashEnc[0..16].*,
                    e.shared_secret.get()[32..64].*,
                    _pinHashEnc[16..32],
                    pin_hash_left,
                );
                pinHashEnc = _pinHashEnc[0..32];
            },
        }
        request.pinHashEnc = try .fromSlice(pinHashEnc);

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            const cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{});

            if (cpr.pinUvAuthToken == null) return error.MissingPar;

            var token: []u8 = undefined;
            switch (e.version) {
                .V1 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len);
                    PinUvAuth.decrypt_v1(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
                .V2 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len - 16);
                    PinUvAuth.decrypt_v2(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
            }
            return token;
        } else {
            return error.MissingResponse;
        }
    }

    pub fn getPinUvAuthTokenUsingUvWithPermissions(
        t: *Transport,
        e: *Encapsulation,
        permissions: Permissions,
        rpId: ?[]const u8,
        a: std.mem.Allocator,
    ) ![]const u8 {
        const cmd = 0x06;
        var request = ClientPin{
            .pinUvAuthProtocol = e.version,
            .subCommand = .getPinUvAuthTokenUsingUvWithPermissions,
            .keyAgreement = cbor.cose.Key.fromP256Pub(
                .EcdhEsHkdf256,
                e.platform_key_agreement_key,
            ),
            .permissions = std.mem.toBytes(permissions)[0],
        };

        if (rpId) |id| {
            request.rpId = try .fromSlice(id);
        }

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(cmd);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var cpr = try cbor.parse(ClientPinResponse, try cbor.DataItem.new(response[1..]), .{});

            if (cpr.pinUvAuthToken == null) return error.MissingPar;

            var token: []u8 = undefined;
            switch (e.version) {
                .V1 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len);
                    PinUvAuth.decrypt_v1(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
                .V2 => {
                    token = try a.alloc(u8, cpr.pinUvAuthToken.?.len - 16);
                    PinUvAuth.decrypt_v2(e.shared_secret.get(), token, cpr.pinUvAuthToken.?.get());
                },
            }
            return token;
        } else {
            return error.MissingResponse;
        }
    }
};

// ///////////////////////////////////////
// Credential Management
// ///////////////////////////////////////

pub const CredentialManagement = keylib.ctap.request.CredentialManagement;
pub const CredentialManagementResponse = keylib.ctap.response.CredentialManagement;

pub const cred_management = struct {
    pub const RelyingParty = struct {
        rp: keylib.common.RelyingParty,
        rpIDHash: [32]u8,
        total: ?u32 = null,
    };

    pub const UserData = struct {
        user: keylib.common.User,
        credentialID: keylib.common.PublicKeyCredentialDescriptor,
        publicKey: cbor.cose.Key,
        credProtect: keylib.ctap.extensions.CredentialCreationPolicy,
        totalCredentials: ?u32 = null,
    };

    pub const Metadata = struct {
        existingResidentCredentialsCount: u32,
        maxPossibleRemainingResidentCredentialsCount: u32,
    };

    /// Get credential metadata information.
    ///
    // The authenticator MUST support `authenticatorCredentialManagement´.
    pub fn getCredsMetadata(
        t: *Transport,
        token: []const u8,
        pinUvAuthProtocol: keylib.ctap.pinuv.common.PinProtocol,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !Metadata {
        //if ((info.options.credMgmt == null or !info.options.credMgmt.?) and (info.options.credentialMgmtPreview == null or !info.options.credentialMgmtPreview.?)) {
        //    return error.CredentialManagementNotSupportedByAuthenticator;
        //}

        const param = switch (pinUvAuthProtocol) {
            .V1 => PinUvAuth.authenticate_v1(token, "\x01"),
            .V2 => PinUvAuth.authenticate_v2(token, "\x01"),
        };

        const request = CredentialManagement{
            .subCommand = .getCredsMetadata,
            .pinUvAuthProtocol = pinUvAuthProtocol,
            .pinUvAuthParam = param.get(),
        };

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            var r = try cbor.parse(
                CredentialManagementResponse,
                try cbor.DataItem.new(response[1..]),
                .{ .allocator = a },
            );
            defer r.deinit(a);

            if (r.existingResidentCredentialsCount == null) return error.MissingPar;
            if (r.maxPossibleRemainingResidentCredentialsCount == null) return error.MissingPar;

            return .{
                .existingResidentCredentialsCount = r.existingResidentCredentialsCount.?,
                .maxPossibleRemainingResidentCredentialsCount = r.maxPossibleRemainingResidentCredentialsCount.?,
            };
        } else return error.MissingResponse;
    }

    pub fn enumerateRPsBegin(
        t: *Transport,
        token: []const u8,
        protocol: keylib.ctap.pinuv.common.PinProtocol,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !?RelyingParty {
        const param = switch (protocol) {
            .V1 => PinUvAuth.authenticate_v1(token, "\x02"),
            .V2 => PinUvAuth.authenticate_v2(token, "\x02"),
        };

        const request = CredentialManagement{
            .subCommand = .enumerateRPsBegin,
            .pinUvAuthProtocol = protocol,
            .pinUvAuthParam = param.get(),
        };

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.rp == null) return null; // this doesn't reflect the spec but its the behaviour of yubikeys
            if (r.rpIDHash == null) return error.MissingPar;
            if (r.totalRPs == null) return error.MissingPar;

            return .{
                .rp = .{
                    .id = r.rp.?.id,
                    .name = r.rp.?.name,
                },
                .rpIDHash = r.rpIDHash.?,
                .total = r.totalRPs.?,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateRPsGetNextRP(
        t: *Transport,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !?RelyingParty {
        const request = CredentialManagement{
            .subCommand = .enumerateRPsGetNextRP,
        };

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.rp == null) return null; // this doesn't reflect the spec but its the behaviour of yubikeys
            if (r.rpIDHash == null) return error.MissingPar;

            return .{
                .rp = .{
                    .id = r.rp.?.id,
                    .name = r.rp.?.name,
                },
                .rpIDHash = r.rpIDHash.?,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateCredentialsBegin(
        t: *Transport,
        token: []const u8,
        protocol: keylib.ctap.pinuv.common.PinProtocol,
        rpIDHash: [32]u8,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !?UserData {
        var request = CredentialManagement{
            .subCommand = .enumerateCredentialsBegin,
            .subCommandParams = .{
                .rpIDHash = rpIDHash,
            },
        };

        // Create Param

        var scp = std.Io.Writer.Allocating.init(a);
        defer scp.deinit();
        try scp.writer.writeByte(0x04);
        try cbor.stringify(request.subCommandParams.?, .{}, &scp.writer);
        //std.debug.print("{x}\n", .{scp.written()});
        const param = switch (protocol) {
            .V1 => PinUvAuth.authenticate_v1(token, scp.written()),
            .V2 => PinUvAuth.authenticate_v2(token, scp.written()),
        };
        request.pinUvAuthProtocol = protocol;
        request.pinUvAuthParam = param.get();

        // Send request

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.user == null) return error.MissingPar;
            if (r.credentialID == null) return error.MissingPar;
            if (r.publicKey == null) return error.MissingPar;
            if (r.totalCredentials == null) return error.MissingPar;
            if (r.credProtect == null) return error.MissingPar;

            return .{
                .user = r.user.?,
                .credentialID = r.credentialID.?,
                .publicKey = r.publicKey.?,
                .totalCredentials = r.totalCredentials.?,
                .credProtect = r.credProtect.?,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn enumerateCredentialsGetNextCredential(
        t: *Transport,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !?UserData {
        const request = CredentialManagement{
            .subCommand = .enumerateCredentialsGetNextCredential,
        };

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] == 0x2e) {
                // no credentials
                return null;
            }

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }

            var r = try cbor.parse(CredentialManagementResponse, try cbor.DataItem.new(response[1..]), .{ .allocator = a });
            defer r.deinit(a);

            if (r.user == null) return error.MissingPar;
            if (r.credentialID == null) return error.MissingPar;
            if (r.publicKey == null) return error.MissingPar;
            if (r.credProtect == null) return error.MissingPar;

            return .{
                .user = r.user.?,
                .credentialID = r.credentialID.?,
                .publicKey = r.publicKey.?,
                .credProtect = r.credProtect.?,
            };
        } else {
            return error.MissingResponse;
        }
    }

    pub fn deleteCredential(
        t: *Transport,
        token: []const u8,
        protocol: keylib.ctap.pinuv.common.PinProtocol,
        credentialId: []const u8,
        is_yubikey: bool,
        a: std.mem.Allocator,
    ) !void {
        var request = CredentialManagement{
            .subCommand = .deleteCredential,
            .subCommandParams = .{
                .credentialID = .{
                    .id = (try keylib.common.dt.ABS64B.fromSlice(credentialId)).?,
                    .type = .@"public-key",
                },
            },
        };

        // Create Param

        var scp = std.Io.Writer.Allocating.init(a);
        defer scp.deinit();
        try scp.writer.writeByte(0x06);
        try cbor.stringify(request.subCommandParams.?, .{}, &scp.writer);
        //std.debug.print("{x}\n", .{scp.written()});
        const param = switch (protocol) {
            .V1 => PinUvAuth.authenticate_v1(token, scp.written()),
            .V2 => PinUvAuth.authenticate_v2(token, scp.written()),
        };
        request.pinUvAuthProtocol = protocol;
        request.pinUvAuthParam = param.get();

        // Send request

        var arr = std.Io.Writer.Allocating.init(a);
        defer arr.deinit();

        try arr.writer.writeByte(if (is_yubikey) 0x41 else 0x0a);
        try cbor.stringify(request, .{}, &arr.writer);

        try t.write(arr.written());

        if (try t.read(a)) |response| {
            defer a.free(response);

            if (response[0] != 0) {
                return err.errorFromInt(response[0]);
            }
        } else {
            return error.MissingResponse;
        }
    }
};
