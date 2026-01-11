//! This example shows how to set a new PIN for an authenticator.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");

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
    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    var pin: ?[]const u8 = null;
    var yubikey = false;

    // Allow device selection based on an index. Use this together with the
    // manifest example.
    if (argv.len < 2) {
        try stderr.print("usage: metadata <device> [pin] [yubikey=[y/n]]\n", .{});
        try stderr.flush();
        return;
    }
    const device_index: usize = try std.fmt.parseInt(usize, argv[1], 0);

    if (argv.len >= 3) {
        pin = argv[2];
    }

    if (argv.len >= 4) {
        yubikey = if (argv[3][0] == 'y') true else false;
    }

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

    const rp = try client.cbor_commands.cred_management.enumerateRPsBegin(
        device,
        token,
        pinUvAuthProtocol,
        yubikey,
        allocator,
    );

    if (rp == null) {
        return;
    }

    try stdout.print("{s}, {x}\n", .{
        rp.?.rp.id.get(),
        &rp.?.rpIDHash,
    });
    try stdout.flush();

    if (rp.?.total) |total| {
        var i: usize = 1; // total contains the number of resident keys, i.e. we have to start at one (1)
        while (i < total) : (i += 1) {
            if (try client.cbor_commands.cred_management.enumerateRPsGetNextRP(
                device,
                yubikey,
                allocator,
            )) |next_rp| {
                try stdout.print("{s}, {x}\n", .{
                    next_rp.rp.id.get(),
                    &next_rp.rpIDHash,
                });
                try stdout.flush();
            }
        }
    }
}
