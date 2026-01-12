//! This example shows how to set a new PIN for an authenticator.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");
const clap = @import("clap");

const client = @import("client");
const client_pin = client.cbor_commands.client_pin;
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const Info = client.cbor_commands.Info;

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
    var pin: ?[]const u8 = null;
    var yubikey = false;

    const params = comptime clap.parseParamsComptime(
        \\--help                 Display this help and exit.
        \\-p <str>               Specify a PIN for authentication
        \\-y                     credential management preview / YubiKey command
        \\<str>...
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(stderr, err) catch {};
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try stdout.print("{s}", .{help_text});
        try stdout.flush();
        return;
    }

    if (res.args.p) |p| pin = p;
    if (res.args.y != 0) yubikey = true;

    if (res.positionals[0].len < 2) {
        try stdout.print("{s}", .{help_text});
        try stdout.flush();
        return;
    }

    const device_index = try std.fmt.parseInt(usize, res.positionals[0][0], 0);
    const origin = res.positionals[0][1];

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

    var info_state = try (try authenticatorGetInfo(device)).await(allocator);
    defer info_state.deinit(allocator);
    const info = try info_state.deserializeCbor(Info, allocator);
    defer info.deinit(allocator);

    // ============================================
    // Obtain pinUvAuthToken
    // ============================================

    const pinUvAuthProtocol, const token = try client.cbor_commands.pinUvAuthToken(
        device,
        allocator,
        info,
        .{
            .permissions = .{
                .cm = 1,
            },
            .pin = pin,
        },
    );

    // ============================================
    // Prepare the data for the request
    // ============================================

    var rpIDHash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(origin, &rpIDHash, .{});

    const user = try client.cbor_commands.cred_management.enumerateCredentialsBegin(
        device,
        token,
        pinUvAuthProtocol,
        rpIDHash,
        yubikey,
        allocator,
    );

    if (user == null) {
        return;
    }

    //try std.json.Stringify.value(user.?, .{}, stdout);

    try stdout.print("Credential (1)\n", .{});
    try stdout.print("  userId: {x}\n", .{user.?.user.id.get()});
    try stdout.print("  credId: {x}\n", .{user.?.credentialID.id.get()});
    switch (user.?.publicKey) {
        .P256 => |k| {
            // sec1 (https://www.secg.org/sec1-v2.pdf) 2.3.3
            // 04 || X || Y
            try stdout.print("  coseKey ({any}): 04{x}{x}\n", .{
                k.alg,
                &k.x,
                &k.y,
            });
        },
    }
    try stdout.flush();

    if (user.?.totalCredentials) |total| {
        var i: usize = 1; // total contains the number of resident keys, i.e. we have to start at one (1)
        while (i < total) : (i += 1) {
            if (try client.cbor_commands.cred_management.enumerateCredentialsGetNextCredential(
                device,
                yubikey,
                allocator,
            )) |next_user| {
                try stdout.print("Credential ({d})\n", .{i + 1});
                try stdout.print("  userId: {x}\n", .{next_user.user.id.get()});
                try stdout.print("  credId: {x}\n", .{next_user.credentialID.id.get()});
                switch (next_user.publicKey) {
                    .P256 => |k| {
                        // sec1 (https://www.secg.org/sec1-v2.pdf) 2.3.3
                        // 04 || X || Y
                        try stdout.print("  coseKey ({any}): 04{x}{x}\n", .{
                            k.alg,
                            &k.x,
                            &k.y,
                        });
                    },
                }
                try stdout.flush();
            }
        }
    }
}

const help_text =
    \\usage: enumcred <device> <origin>
    \\
    \\--help                 Display this help and exit.
    \\-p <str>               Specify a PIN for authentication
    \\<str>...
    \\
;
