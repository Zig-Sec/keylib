const std = @import("std");

pub const Create = struct {
    publicKey: struct {
        /// A random nonce to prevent replay attacks
        challenge: []const u8,
        rp: struct {
            /// A Relying Party ID (e.g. "acme.com")
            id: []const u8,
            /// A Relying Party name (e.g., "ACME Corporation")
            name: ?[]const u8 = null,
        },
        user: struct {
            /// A user ID
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
    },

    pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.publicKey.challenge);

        allocator.free(self.publicKey.rp.id);
        if (self.publicKey.rp.name) |v| allocator.free(v);

        allocator.free(self.publicKey.user.id);
        if (self.publicKey.user.name) |v| allocator.free(v);
        if (self.publicKey.user.displayName) |v| allocator.free(v);

        for (self.publicKey.pubKeyCredParams) |param| {
            allocator.free(param.alg);
        }
        allocator.free(self.publicKey.pubKeyCredParams);
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
};

test "serialize mdn create example" {
    const test_data = Create{
        .publicKey = .{
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
        },
    };

    var s = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer s.deinit();

    try test_data.toJsonAlloc(&s.writer);

    try std.testing.expectEqualStrings(
        \\{
        \\  "publicKey": {
        \\    "challenge": [
        \\      117,
        \\      61,
        \\      252,
        \\      231,
        \\      191,
        \\      241
        \\    ],
        \\    "rp": {
        \\      "id": "acme.com",
        \\      "name": "ACME Corporation"
        \\    },
        \\    "user": {
        \\      "id": [
        \\        79,
        \\        252,
        \\        83,
        \\        72,
        \\        214,
        \\        7,
        \\        89,
        \\        26
        \\      ],
        \\      "name": "jamiedoe",
        \\      "displayName": "Jamie Doe"
        \\    },
        \\    "pubKeyCredParams": [
        \\      {
        \\        "type": "public-key",
        \\        "alg": -7
        \\      }
        \\    ]
        \\  }
        \\}
    , s.written());
}
