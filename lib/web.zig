const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const client = @import("client.zig");

pub const create = struct {
    pub const Response = struct {
        id: []const u8,
        rawId: []const u8,
        response: struct {
            attestationObject: []const u8,
            clientDataJSON: []const u8,
            transports: []const []const u8,
        },
        type: []const u8, // "public-key"
        clientExtensionResults: struct {} = .{}, // TODO
        authenticatorAttachment: client.AuthenticatorAttachment,

        pub fn new(
            /// CBOR response from calling `authenticatorMakeCredential`
            attestationObject: []const u8,
            /// Client Data Json send to the authenticator
            clientDataJson: []const u8,
            /// Authenticator transports suported by the authenticator
            transports: []const keylib.common.AuthenticatorTransports,
            /// The attchment of the authenticator used to create the attestation
            authenticatorAttachment: client.AuthenticatorAttachment,
            allocator: std.mem.Allocator,
        ) !@This() {
            const base64 = std.base64.url_safe_no_pad.Encoder;

            // Translate attestation object BEGIN

            const ao_ = try cbor.parse(
                client.MakeCredentialResponse,
                try cbor.DataItem.new(attestationObject),
                .{ .allocator = allocator },
            );
            defer ao_.deinit(allocator);

            if (ao_.authData.extensions) |extensions| {
                _ = extensions; // TODO
            }

            const ao = try ao_.toAttestationObject(allocator);
            defer allocator.free(ao);

            // Translate attestation object END

            const credId = try allocator.dupe(u8, ao_.authData.getCredId() orelse return error.MissingCredId);
            defer allocator.free(credId);

            var l = base64.calcSize(credId.len);
            const b64CredId = try allocator.alloc(u8, l);
            _ = base64.encode(b64CredId, credId);

            l = base64.calcSize(ao.len);
            const b64ao = try allocator.alloc(u8, l);
            _ = base64.encode(b64ao, ao);

            l = base64.calcSize(clientDataJson.len);
            const cdj = try allocator.alloc(u8, l);
            _ = base64.encode(cdj, clientDataJson);

            var t: std.ArrayListUnmanaged([]const u8) = .empty;
            for (transports) |trans| {
                try t.append(allocator, switch (trans) {
                    .usb => try allocator.dupe(u8, "usb"),
                    .nfc => try allocator.dupe(u8, "nfc"),
                    .ble => try allocator.dupe(u8, "ble"),
                    .@"smart-card" => try allocator.dupe(u8, "smart-card"),
                    .hybrid => try allocator.dupe(u8, "hybrid"),
                    .internal => try allocator.dupe(u8, "internal"),
                });
            }

            return .{
                .id = b64CredId,
                .rawId = try allocator.dupe(u8, b64CredId),
                .response = .{
                    .attestationObject = b64ao,
                    .clientDataJSON = cdj,
                    .transports = try t.toOwnedSlice(allocator),
                },
                .type = try allocator.dupe(u8, "public-key"),
                .authenticatorAttachment = authenticatorAttachment,
            };
        }

        pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.id);
            allocator.free(self.rawId);
            allocator.free(self.response.attestationObject);
            allocator.free(self.response.clientDataJSON);
            for (self.response.transports) |t| allocator.free(t);
            allocator.free(self.response.transports);
            allocator.free(self.type);
        }

        pub fn toJsonAlloc(
            self: *const @This(),
            allocator: std.mem.Allocator,
        ) ![]const u8 {
            var out = std.Io.Writer.Allocating.init(allocator);

            var fmt = std.json.fmt(
                self,
                .{
                    .emit_null_optional_fields = false,
                },
            );
            try fmt.format(&out.writer);

            return out.toOwnedSlice();
        }
    };

    pub const Request = struct {
        /// A random nonce to prevent replay attacks (BASE64 encoded)
        challenge: []const u8,
        rp: struct {
            /// A Relying Party ID (e.g. "acme.com")
            id: []const u8,
            /// A Relying Party name (e.g., "ACME Corporation")
            name: ?[]const u8 = null,
        },
        user: struct {
            /// A user ID (BASE64 encoded)
            id: []const u8,
            /// The user name (e.g., "david@zigtoberfest.de")
            name: ?[]const u8 = null,
            /// The display name of the user
            displayName: ?[]const u8 = null,
        },
        pubKeyCredParams: []const keylib.common.PublicKeyCredentialParameters,
        timeout: ?u64 = null,
        excludeCredentials: ?[]const struct {
            /// Credential ID (BASE64 encoded)
            id: []const u8,
            /// "public-key"
            type: []const u8,
        } = null,
        authenticatorSelection: ?struct {
            authenticatorAttachment: ?[]const u8 = null,
            residentKey: ?[]const u8 = null,
            requireResidentKey: ?bool = null,
            userVerification: ?[]const u8 = null,
        } = null,
        attestation: ?[]const u8 = null,
        hints: ?[]const []const u8 = null,

        pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
            allocator.free(self.challenge);

            allocator.free(self.rp.id);
            if (self.rp.name) |v| allocator.free(v);

            allocator.free(self.user.id);
            if (self.user.name) |v| allocator.free(v);
            if (self.user.displayName) |v| allocator.free(v);

            allocator.free(self.pubKeyCredParams);

            if (self.excludeCredentials) |exCreds| {
                for (exCreds) |exCred| {
                    allocator.free(exCred.id);
                    allocator.free(exCred.type);
                }
                allocator.free(exCreds);
            }

            if (self.authenticatorSelection) |authSelect| {
                if (authSelect.authenticatorAttachment) |v| allocator.free(v);
                if (authSelect.residentKey) |v| allocator.free(v);
                if (authSelect.userVerification) |v| allocator.free(v);
            }

            if (self.attestation) |v| allocator.free(v);

            if (self.hints) |hints| {
                for (hints) |hint| allocator.free(hint);
                allocator.free(hints);
            }
        }

        pub fn toJsonAlloc(self: *const @This(), writer: *std.Io.Writer) !void {
            var fmt = std.json.fmt(
                self,
                .{
                    .emit_null_optional_fields = false,
                    .whitespace = .indent_2,
                },
            );

            try fmt.format(writer);
        }

        pub fn fromJsonAlloc(
            allocator: std.mem.Allocator,
            slice: []const u8,
        ) !@This() {
            return try std.json.parseFromSliceLeaky(
                Request,
                allocator,
                slice,
                .{
                    .allocate = .alloc_always,
                    .ignore_unknown_fields = true,
                },
            );
        }
    };
};

//test "serialize mdn create example" {
//    const test_data = Create{
//        .challenge = &.{ 117, 61, 252, 231, 191, 241 },
//        .rp = .{
//            .id = "acme.com",
//            .name = "ACME Corporation",
//        },
//        .user = .{
//            .id = &.{ 79, 252, 83, 72, 214, 7, 89, 26 },
//            .name = "jamiedoe",
//            .displayName = "Jamie Doe",
//        },
//        .pubKeyCredParams = &.{
//            .{ .type = .@"public-key", .alg = .Es256 },
//        },
//    };
//
//    var s = std.Io.Writer.Allocating.init(std.testing.allocator);
//    defer s.deinit();
//
//    try test_data.toJsonAlloc(&s.writer);
//
//    try std.testing.expectEqualStrings(
//        \\{
//        \\  "challenge": [
//        \\    117,
//        \\    61,
//        \\    252,
//        \\    231,
//        \\    191,
//        \\    241
//        \\  ],
//        \\  "rp": {
//        \\    "id": "acme.com",
//        \\    "name": "ACME Corporation"
//        \\  },
//        \\  "user": {
//        \\    "id": [
//        \\      79,
//        \\      252,
//        \\      83,
//        \\      72,
//        \\      214,
//        \\      7,
//        \\      89,
//        \\      26
//        \\    ],
//        \\    "name": "jamiedoe",
//        \\    "displayName": "Jamie Doe"
//        \\  },
//        \\  "pubKeyCredParams": [
//        \\    {
//        \\      "type": "public-key",
//        \\      "alg": -7
//        \\    }
//        \\  ]
//        \\}
//    , s.written());
//}

test "deserialize registrarion options generated using py_webauthn #1" {
    const creation_options =
        \\{"rp": {"name": "Zigtoberfest", "id": "zigtoberfest.de"}, "user": {"id": "OWLN0YlNPGih49H1tGZhySGMDXdZY9bWC6neT3MF2Ab-PlcgzpdMWIYiK0fcxOVzjlN9dNkBeQfL69Po2Ci0ig", "name": "david", "displayName": "david"}, "challenge": "J2ItcBXgQrPghBK1704tp3JvCyyAJMSa3cGKErcgQZA4KNFUN_vqGJA47VfH3wMTFkERavOaX1Yhidx6rF7nMw", "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -36}, {"type": "public-key", "alg": -37}, {"type": "public-key", "alg": -38}, {"type": "public-key", "alg": -39}, {"type": "public-key", "alg": -257}, {"type": "public-key", "alg": -258}, {"type": "public-key", "alg": -259}], "timeout": 60000, "excludeCredentials": [], "attestation": "none"}
    ;

    const opts = try create.Request.fromJsonAlloc(std.testing.allocator, creation_options);
    defer opts.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("Zigtoberfest", opts.rp.name.?);
    try std.testing.expectEqualStrings("zigtoberfest.de", opts.rp.id);
    try std.testing.expectEqualStrings("OWLN0YlNPGih49H1tGZhySGMDXdZY9bWC6neT3MF2Ab-PlcgzpdMWIYiK0fcxOVzjlN9dNkBeQfL69Po2Ci0ig", opts.user.id);
    try std.testing.expectEqualStrings("david", opts.user.name.?);
    try std.testing.expectEqualStrings("david", opts.user.displayName.?);

    // TODO
}

test "deserialize registrarion options generated using py_webauthn #2" {
    const creation_options =
        \\{"rp": {"name": "Example Co", "id": "example.com"}, "user": {"id": "AQIDBA", "name": "lee", "displayName": "Lee"}, "challenge": "AQIDBAUGBwgJAA", "pubKeyCredParams": [{"type": "public-key", "alg": -36}], "timeout": 12000, "excludeCredentials": [{"id": "MTIzNDU2Nzg5MA", "type": "public-key"}], "authenticatorSelection": {"authenticatorAttachment": "platform", "residentKey": "required", "requireResidentKey": true, "userVerification": "preferred"}, "attestation": "direct", "hints": ["client-device"]}
    ;

    const opts = try create.Request.fromJsonAlloc(std.testing.allocator, creation_options);
    defer opts.deinit(std.testing.allocator);
}
