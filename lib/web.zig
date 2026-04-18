const std = @import("std");

pub const Create = struct {
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
    pubKeyCredParams: []const struct {
        /// This must be the string "public-key"!
        type: []const u8,
        alg: i32,
    },
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

        for (self.pubKeyCredParams) |param| {
            allocator.free(param.type);
        }
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
            Create,
            allocator,
            slice,
            .{
                .allocate = .alloc_always,
                .ignore_unknown_fields = true,
            },
        );
    }
};

test "serialize mdn create example" {
    const test_data = Create{
        .challenge = &.{ 117, 61, 252, 231, 191, 241 },
        .rp = .{
            .id = "acme.com",
            .name = "ACME Corporation",
        },
        .user = .{
            .id = &.{ 79, 252, 83, 72, 214, 7, 89, 26 },
            .name = "jamiedoe",
            .displayName = "Jamie Doe",
        },
        .pubKeyCredParams = &.{
            .{ .type = "public-key", .alg = -7 },
        },
    };

    var s = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer s.deinit();

    try test_data.toJsonAlloc(&s.writer);

    try std.testing.expectEqualStrings(
        \\{
        \\  "challenge": [
        \\    117,
        \\    61,
        \\    252,
        \\    231,
        \\    191,
        \\    241
        \\  ],
        \\  "rp": {
        \\    "id": "acme.com",
        \\    "name": "ACME Corporation"
        \\  },
        \\  "user": {
        \\    "id": [
        \\      79,
        \\      252,
        \\      83,
        \\      72,
        \\      214,
        \\      7,
        \\      89,
        \\      26
        \\    ],
        \\    "name": "jamiedoe",
        \\    "displayName": "Jamie Doe"
        \\  },
        \\  "pubKeyCredParams": [
        \\    {
        \\      "type": "public-key",
        \\      "alg": -7
        \\    }
        \\  ]
        \\}
    , s.written());
}

test "deserialize registrarion options generated using py_webauthn #1" {
    const creation_options =
        \\{"rp": {"name": "Zigtoberfest", "id": "zigtoberfest.de"}, "user": {"id": "OWLN0YlNPGih49H1tGZhySGMDXdZY9bWC6neT3MF2Ab-PlcgzpdMWIYiK0fcxOVzjlN9dNkBeQfL69Po2Ci0ig", "name": "david", "displayName": "david"}, "challenge": "J2ItcBXgQrPghBK1704tp3JvCyyAJMSa3cGKErcgQZA4KNFUN_vqGJA47VfH3wMTFkERavOaX1Yhidx6rF7nMw", "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -36}, {"type": "public-key", "alg": -37}, {"type": "public-key", "alg": -38}, {"type": "public-key", "alg": -39}, {"type": "public-key", "alg": -257}, {"type": "public-key", "alg": -258}, {"type": "public-key", "alg": -259}], "timeout": 60000, "excludeCredentials": [], "attestation": "none"}
    ;

    const opts = try Create.fromJsonAlloc(std.testing.allocator, creation_options);
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

    const opts = try Create.fromJsonAlloc(std.testing.allocator, creation_options);
    defer opts.deinit(std.testing.allocator);
}
