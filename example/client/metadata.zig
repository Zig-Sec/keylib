//! This example shows how to set a new PIN for an authenticator.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");

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

    var info_state = try (try client.getInfo(device, .{})).await(allocator);
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
                .cm = 1,
            },
            .pin = pin,
        },
    );
    defer allocator.free(token);

    // ============================================
    // Prepare the data for the request
    // ============================================

    const metadata = try client.cm.getCredsMetadata(
        device,
        token,
        pinUvAuthProtocol,
        yubikey, // some older yubikeys use a different command code for credential management
        allocator,
    );

    try stdout.print("{any}\n", .{metadata});
    try stdout.flush();
}
