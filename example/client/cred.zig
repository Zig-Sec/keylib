//! This example shows how to set a new PIN for an authenticator.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");
const clap = @import("clap");

const client = @import("client");

// Allocator to be used for allocating dynamic memory.
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

// Buffered stdout (don't forget to flush!).
var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

var stderr_buffer: [1024]u8 = undefined;
var stderr_writer = std.fs.File.stdout().writer(&stderr_buffer);
const stderr = &stderr_writer.interface;

pub fn main() !void {
    defer _ = gpa.detectLeaks();

    var rk = false;
    var uv = false;
    var hms: bool = false;
    var pin: ?[]const u8 = null;
    var typ: client.PublicKeyCredentialParameters = .{
        .alg = .Es256,
        .type = .@"public-key",
    };
    var origin: []const u8 = "localhost";
    const crossOrigin = false;
    var uidBuffer: [128]u8 = .{0} ** 128;
    var user_id: []const u8 = &.{
        0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
        0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
        0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
        0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,
    };

    const params = comptime clap.parseParamsComptime(
        \\--help                 Display this help and exit.
        \\-t <str>               Signature algorithm to use [es256 (default)]
        \\-h                     Use the hmac-secret extension
        \\-r                     Create a resident key (passkey)
        \\-v                     Request user verification
        \\-c <str>               Set a specific protection policy [TBD]
        \\-p <str>               Specify a PIN for authentication
        \\--origin <str>         An origin for the request (e.g. localhost)
        \\--uid <str>            User ID in hexadecimal
        \\<str>
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(stderr, err) catch {};
        try stderr.flush();
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try stdout.print("{s}", .{help_text});
        try stdout.flush();
        return;
    }

    if (res.args.r != 0) rk = true;
    if (res.args.v != 0) uv = true;
    if (res.args.h != 0) hms = true;
    if (res.args.p) |p| pin = p;
    if (res.args.t) |t| {
        if (std.mem.eql(u8, t, "es256")) {
            typ = .{
                .alg = .Es256,
                .type = .@"public-key",
            };
        } else {
            try stderr.print("err: unsupported signature algorithm '{s}'", .{t});
            try stderr.flush();
            return;
        }
    }
    if (res.args.origin) |o| origin = o;
    if (res.args.uid) |id| {
        user_id = try std.fmt.hexToBytes(&uidBuffer, id);
    }

    const device_index = if (res.positionals[0]) |dev| blk: {
        break :blk try std.fmt.parseInt(usize, dev, 0);
    } else {
        try stdout.print("usage: cred [thrvcp] <device>\n", .{});
        try stdout.flush();
        return;
    };

    // ============================================
    // Open device
    // ============================================

    var transports = try client.Transports.enumerate(
        allocator,
        .{},
    );
    defer transports.deinit();

    // Select a FIDO device.
    if (transports.devices.len == 0) {
        std.log.err("No device available", .{});
        return;
    }

    if (transports.devices.len <= device_index) {
        std.log.err("No device at index {d}", .{device_index});
        return;
    }

    var device = &transports.devices[device_index];

    // Next we have to open the selected device, to establish a connection.
    device.open() catch {
        // We won't deallocate the name as the process is terminated anyway.
        const device_name = device.allocPrint(allocator) catch "";
        std.log.err(
            "Failed to open device '{s}'",
            .{device_name},
        );
        return;
    };
    defer device.close(); // Don't forget to close the connection.

    // ============================================
    // Obtain information about the device
    // ============================================

    var info_state = try (try client.getInfo(device)).await(allocator);
    defer info_state.deinit(allocator);
    const info = try info_state.deserializeCbor(client.Info, allocator);
    defer info.deinit(allocator);

    // ============================================
    // Obtain pinUvAuthToken
    // ============================================

    const pinUvAuthProtocol, const token = try client.pinUvAuthToken(
        device,
        allocator,
        info,
        .{
            .permissions = .{
                .mc = 1,
            },
            .pin = pin,
            .rpId = origin,
        },
    );
    defer allocator.free(token);

    // ============================================
    // Prepare the data for the request
    // ============================================

    // A challenge is a nonce used to prevent replay attacks.
    // It should be chosen at random.
    var challenge: [32]u8 = undefined;
    std.crypto.random.bytes(&challenge);

    const clientData = try client.clientDataAlloc(
        allocator,
        "webauthn.create",
        &challenge,
        origin,
        false,
    );
    defer allocator.free(clientData);

    var promise = try client.makeCredential(
        device,
        token,
        pinUvAuthProtocol,
        clientData,
        allocator,
        .{
            .rpId = origin,
            .crossOrigin = crossOrigin,
            .userId = user_id,
            .rk = rk,
        },
    );

    const mc_response = outer: while (true) {
        const state = promise.get(allocator);
        defer state.deinit(allocator);

        switch (state) {
            .pending => |p| {
                switch (p) {
                    .processing => std.log.info("processing", .{}),
                    .user_presence => std.log.info("user presence", .{}),
                    .waiting => std.log.info("waiting", .{}),
                }
            },
            .fulfilled => {
                //std.debug.print("response: {x}", .{state.fulfilled});
                break :outer try state.deserializeCbor(
                    client.MakeCredentialResponse,
                    allocator,
                );
            },
            .rejected => |e| {
                return e;
            },
        }
    };
    defer mc_response.deinit(allocator);

    const credId = mc_response.authData.getCredId();
    const coseKey = try mc_response.authData.getCredentialPublicKey();

    try stdout.print("credId: {x}\n", .{credId.?});
    switch (coseKey.?) {
        .P256 => |k| {
            // sec1 (https://www.secg.org/sec1-v2.pdf) 2.3.3
            // 04 || X || Y
            try stdout.print("coseKey ({any}): 04{x}{x}\n", .{
                k.alg,
                &k.x,
                &k.y,
            });
        },
    }
    try stdout.flush();
}

const help_text =
    \\usage: cred [thrvcp] <device>
    \\
    \\--help                 Display this help and exit.
    \\-t <str>               Signature algorithm to use [es256 (default)]
    \\-h                     Use the hmac-secret extension
    \\-r                     Create a resident key (passkey)
    \\-v                     Request user verification
    \\-c <str>               Set a specific protection policy [TBD]
    \\-p <str>               Specify a PIN for authentication
    \\--origin <str>         An origin for the request (e.g. localhost)
    \\--uid <str>            User ID in hexadecimal
    \\<str>
    \\
;
