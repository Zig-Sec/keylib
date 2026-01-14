//! This example shows how to delete a credential.
//!
//! Copyright (c) 2022 - 2026 David P. Sugar.
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
    var credIdBuffer: [64]u8 = .{0} ** 64;
    const credId = try std.fmt.hexToBytes(
        &credIdBuffer,
        res.positionals[0][1],
    );

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
                .cm = 1,
            },
            .pin = pin,
        },
    );

    // ============================================
    // Prepare the data for the request
    // ============================================

    client.cm.deleteCredential(
        device,
        token,
        pinUvAuthProtocol,
        credId,
        yubikey,
        allocator,
    ) catch |e| {
        try stderr.print("error deleting credential ({any})\n", .{e});
    };
}

const help_text =
    \\usage: delete <device> <credId>
    \\
    \\--help                 Display this help and exit.
    \\-p <str>               Specify a PIN for authentication
    \\-y                     credential management preview / YubiKey command
    \\<str>...
    \\
;
