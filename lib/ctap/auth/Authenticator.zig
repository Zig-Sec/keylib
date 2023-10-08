//! Representation of a FIDO2 authenticator

const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const Allocator = std.mem.Allocator;

const Callbacks = fido.ctap.authenticator.callbacks.Callbacks;
const Data = fido.ctap.authenticator.callbacks.Data;
const DataIterator = fido.ctap.authenticator.callbacks.DataIterator;
const Error = fido.ctap.authenticator.callbacks.Error;
const Settings = fido.ctap.authenticator.Settings;
const PinUvAuth = fido.ctap.pinuv.PinUvAuth;
const SigAlg = fido.ctap.crypto.SigAlg;
const AttestationType = fido.common.AttestationType;
const PublicKeyCredentialParameters = fido.common.PublicKeyCredentialParameters;

const Response = fido.ctap.authenticator.Response;
const StatusCodes = fido.ctap.StatusCodes;
const Commands = fido.ctap.commands.Commands;

pub const Auth = struct {
    /// Callbacks provided by the underlying platform
    callbacks: Callbacks,

    /// Authenticator settings that represent the authenticators capabilities
    settings: Settings,

    /// Pin uv auth protocol
    token: PinUvAuth,

    /// A list of signature algorithms
    ///
    /// This list should match the algorithms defined within the settings.
    algorithms: []const fido.ctap.crypto.SigAlg,

    attestation: AttestationType = .Self,

    allocator: Allocator,

    pub fn default(callbacks: Callbacks, allocator: Allocator) @This() {
        return .{
            .callbacks = callbacks,
            .settings = .{
                .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
                .extensions = &.{.credProtect},
                .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
                .options = .{
                    .credMgmt = false,
                    .rk = true,
                    .uv = if (callbacks.uv) |_| true else null,
                    // This is a platform authenticator even if we use usb for ipc
                    .plat = true,
                    // We don't support client pin
                    .clientPin = null,
                    .pinUvAuthToken = false,
                    .alwaysUv = false,
                },
                .pinUvAuthProtocols = &.{.V2},
                .transports = &.{.usb},
                .algorithms = &.{.{ .alg = .Es256 }},
                .firmwareVersion = 0xcafe,
                .remainingDiscoverableCredentials = 100,
            },
            .token = PinUvAuth.v2(std.crypto.random),
            .algorithms = &.{
                fido.ctap.crypto.algorithms.Es256,
            },
            .allocator = allocator,
        };
    }

    pub fn init(self: *@This()) !void {
        // Check that settings are available and if not, create them
        const meta = self.loadSettings() catch |e| blk: {
            if (e == error.NoData) {
                std.log.info("Auth.init: no settings found", .{});
            } else {
                std.log.err("Auth.init: malformed settings", .{});
            }

            std.log.info("Auth.init: generating new settings...", .{});
            var meta = fido.ctap.authenticator.Meta{};
            self.writeSettings(meta) catch {
                std.log.err("Auth.init: unable to persist settings", .{});
                return error.InitFail;
            };

            std.log.info("Auth.init: new settings persisted", .{});
            break :blk meta;
        };
        _ = meta;

        // Initialize piNUv
        self.token.initialize();
    }

    /// Try to load settings
    pub fn loadSettings(self: *@This()) !fido.ctap.authenticator.Meta {
        const id: [:0]const u8 = "Settings";
        const rp: [:0]const u8 = "Root";
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(id, rp, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        if (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [256]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            return try cbor.parse(
                fido.ctap.authenticator.Meta,
                try cbor.DataItem.new(slice),
                .{},
            );
        } else {
            return error.NoData;
        }
    }

    // Load the credential with the given id
    pub fn loadCredential(self: *@This(), id: []const u8) !fido.ctap.authenticator.Credential {
        const idZ: [:0]const u8 = try self.allocator.dupeZ(u8, id);
        defer self.allocator.free(idZ);
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(idZ, null, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        if (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [1024]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            return try cbor.parse(
                fido.ctap.authenticator.Credential,
                try cbor.DataItem.new(slice),
                .{ .allocator = self.allocator },
            );
        } else {
            return error.NoData;
        }
    }

    /// Load all credentials associated with the given relying party id
    pub fn loadCredentials(self: *@This(), rpId: []const u8) ![]fido.ctap.authenticator.Credential {
        const rpIdZ: [:0]const u8 = try self.allocator.dupeZ(u8, rpId);
        defer self.allocator.free(rpIdZ);
        var iter = DataIterator{
            .allocator = self.allocator,
        };
        defer iter.deinit();

        if (self.callbacks.read(null, rpIdZ, &iter.d) != Error.SUCCESS) {
            return error.NoData;
        }

        var arr = std.ArrayList(fido.ctap.authenticator.Credential).init(self.allocator);
        errdefer arr.deinit();

        while (iter.next()) |s| {
            // Turn data hex string into a byte slice
            var buffer: [1024]u8 = .{0} ** 256;
            const slice = try std.fmt.hexToBytes(&buffer, s);

            try arr.append(try cbor.parse(
                fido.ctap.authenticator.Credential,
                try cbor.DataItem.new(slice),
                .{ .allocator = self.allocator },
            ));
        }

        if (arr.items.len == 0) {
            return error.NoData;
        } else {
            return try arr.toOwnedSlice();
        }
    }

    /// Write settings back into permanent storage
    pub fn writeSettings(self: *@This(), meta: fido.ctap.authenticator.Meta) !void {
        try self.writeCredential("Settings", "Root", meta);
    }

    pub fn writeCredential(self: *@This(), id: []const u8, rpId: []const u8, entry: anytype) !void {
        const _id = try self.allocator.dupeZ(u8, id);
        defer self.allocator.free(_id);
        const _rpId = try self.allocator.dupeZ(u8, rpId);
        defer self.allocator.free(_rpId);

        var str = std.ArrayList(u8).init(self.allocator);
        defer str.deinit();

        try cbor.stringify(entry, .{}, str.writer());

        // Covert the data into a hex string
        var str2 = std.ArrayList(u8).init(self.allocator);
        defer str2.deinit();
        try str2.writer().print("{s}\x00", .{std.fmt.fmtSliceHexLower(str.items)});

        if (self.callbacks.write(_id, _rpId, str2.items.ptr) != Error.SUCCESS) {
            return error.Write;
        }
    }

    pub fn handle(self: *@This(), command: []const u8) Response {
        // Buffer for the response message
        var res = std.ArrayList(u8).init(self.allocator);
        var response = res.writer();
        response.writeByte(0x00) catch unreachable;

        // Decode the command of the given message
        if (command.len < 1) return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_invalid_length) };
        const cmd = Commands.fromRaw(command[0]) catch {
            res.deinit();
            return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_invalid_command) };
        };

        switch (cmd) {
            .authenticatorMakeCredential => {
                // Parse request
                var di = cbor.DataItem.new(command[1..]) catch {
                    std.log.err("handle.authenticatorMakeCredential: malformed request", .{});
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_invalid_cbor) };
                };

                const mcp = cbor.parse(fido.ctap.request.MakeCredential, di, .{
                    .allocator = self.allocator,
                }) catch {
                    std.log.err("handle.authenticatorMakeCredential: unable to map request to `MakeCredential` data type", .{});
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_invalid_cbor) };
                };
                defer mcp.deinit(self.allocator);

                // Execute command
                const status = fido.ctap.commands.authenticator.authenticatorMakeCredential(
                    self,
                    &mcp,
                    response,
                ) catch {
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_other) };
                };

                if (status != .ctap1_err_success) {
                    res.deinit();
                    return Response{ .err = @intFromEnum(status) };
                }
            },
            .authenticatorGetAssertion => {
                var di = cbor.DataItem.new(command[1..]) catch {
                    std.log.err("handle.authenticatorGetAssertion: malformed request", .{});
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_invalid_cbor) };
                };

                const gap = cbor.parse(fido.ctap.request.GetAssertion, di, .{
                    .allocator = self.allocator,
                }) catch {
                    std.log.err("handle.authenticatorGetAssertion: unable to map request to `GetAssertion` data type", .{});
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_invalid_cbor) };
                };
                defer gap.deinit(self.allocator);

                // Execute command
                const status = fido.ctap.commands.authenticator.authenticatorGetAssertion(
                    self,
                    &gap,
                    response,
                ) catch {
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_other) };
                };

                if (status != .ctap1_err_success) {
                    res.deinit();
                    return Response{ .err = @intFromEnum(status) };
                }
            },
            .authenticatorGetInfo => {
                const status = fido.ctap.commands.authenticator.authenticatorGetInfo(self, response) catch {
                    res.deinit();
                    return Response{ .err = @intFromEnum(StatusCodes.ctap1_err_other) };
                };

                if (status != .ctap1_err_success) {
                    res.deinit();
                    return Response{ .err = @intFromEnum(status) };
                }
            },
            else => {
                res.deinit();
                return Response{ .err = @intFromEnum(StatusCodes.ctap2_err_not_allowed) };
            },
        }

        return Response{ .ok = res.toOwnedSlice() catch unreachable };
    }

    /// Given a set of credential parameters, select the first algorithm that is also supported by the authenticator.
    pub fn selectSignatureAlgorithm(self: *@This(), params: []const PublicKeyCredentialParameters) ?SigAlg {
        for (params) |param| {
            for (self.algorithms) |alg| {
                if (param.alg == alg.alg) {
                    return alg;
                }
            }
        }
        return null;
    }

    /// Returns true if the authenticator supports (built in) user verification
    pub fn uvSupported(self: *@This()) bool {
        return self.settings.options.uv != null and
            self.settings.options.uv.? and
            self.callbacks.uv != null;
    }

    pub fn clientPinSupported(self: *@This()) ?bool {
        _ = self;
        // We dont support clientPin (for now). The rational for this is
        // that the focus of this library shifted towards platform authenticators
        // which can implement builtin user verification (even passwords if
        // they like).
        return null;
    }

    /// Returns true if the authenticator is protected by some form of user verification
    pub fn isProtected(self: *@This()) bool {
        return self.uvSupported() or if (self.clientPinSupported()) |cp| cp else false;
    }

    /// Returns true if the authenticator supports resident keys/ discoverable credentials/ passkey
    pub fn rkSupported(self: *@This()) bool {
        return self.settings.options.rk;
    }

    /// Returns true if always uv is enables, false otherwise
    pub fn alwaysUv(self: *@This()) !bool {
        const settings = self.loadSettings() catch |e| {
            std.log.err("Auth.alwaysUv: unable to load settings ({any})", .{e});
            return e;
        };

        return settings.always_uv;
    }

    /// Returns true if the authenticator doesn't require some form of user verification
    pub fn makeCredUvNotRqd(self: *@This()) bool {
        return self.settings.options.makeCredUvNotRqd;
    }

    pub fn noMcGaPermissionsWithClientPin(self: *@This()) bool {
        return self.settings.options.noMcGaPermissionsWithClientPin;
    }
};
