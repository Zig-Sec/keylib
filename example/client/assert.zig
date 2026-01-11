//! This example shows how to obtain one or multiple assertions from an authenticator.
//!
//! Copyright (c) 2022 - 2026 David P. Sugar.
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
    var hms: bool = false;
    var pin: ?[]const u8 = null;
    var credIdBuffer: [64]u8 = .{0} ** 64;
    var credId: ?[]const u8 = null;

    const params = comptime clap.parseParamsComptime(
        \\--help                 Display this help and exit.
        \\-h                     Use the hmac-secret extension
        \\-p <str>               Specify a PIN for authentication
        \\--cred <str>           Cred ID in hexadecimal
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

    if (res.args.help != 0 or res.positionals[0].len < 3) {
        try stdout.print("{s}", .{help_text});
        try stdout.flush();
        return;
    }

    if (res.args.h != 0) hms = true;
    if (res.args.p) |p| pin = p;
    if (res.args.cred) |id| {
        credId = try std.fmt.hexToBytes(&credIdBuffer, id);
    }

    const device_index = try std.fmt.parseInt(usize, res.positionals[0][0], 0);
    const origin = res.positionals[0][1];
    var keyBuffer: [512]u8 = .{0} ** 512;
    const key = try std.fmt.hexToBytes(&keyBuffer, res.positionals[0][2]);
    _ = key; // TODO: implement signature validation

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
                .ga = 1,
            },
            .pin = pin,
            .rpId = origin,
        },
    );

    // ============================================
    // Prepare the data for the request
    // ============================================

    // A challenge is a nonce used to prevent replay attacks.
    // It should be chosen at random.
    var challenge: [32]u8 = undefined;
    std.crypto.random.bytes(&challenge);

    var promise = try client.cbor_commands.credentials.getAssertion(
        device,
        token,
        pinUvAuthProtocol,
        allocator,
        .{
            .rpId = origin,
            .crossOrigin = false,
            .challenge = &challenge,
        },
    );

    const ga_response = outer: while (true) {
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
                    client.cbor_commands.credentials.GetAssertionResponse,
                    allocator,
                );
            },
            .rejected => |e| {
                return e;
            },
        }
    };

    try stdout.print("{any}\n", .{ga_response});

    if (ga_response.numberOfCredentials) |credNum| {
        var i: usize = 1;
        while (i < credNum) : (i += 1) {
            promise = try client.cbor_commands.credentials.getNextAssertion(
                device,
                allocator,
                .{},
            );

            const next = outer: while (true) {
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
                            client.cbor_commands.credentials.GetAssertionResponse,
                            allocator,
                        );
                    },
                    .rejected => |e| {
                        return e;
                    },
                }
            };

            try stdout.print("{any}\n", .{next});
        }
    }

    try stdout.flush();
}

const help_text =
    \\usage: assert [-hp] [--cred <credId>] <device> <origin/rpId> <pubKey>
    \\
    \\--help                 Display this help and exit.
    \\-h                     Use the hmac-secret extension
    \\-p <str>               Specify a PIN for authentication
    \\--cred <str>           Cred ID in hexadecimal
    \\<str>...
    \\
;
