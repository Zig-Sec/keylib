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

pub fn main() !void {
    defer _ = gpa.detectLeaks();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len < 3) {
        try stdout.print(
            "usage: setpin <device_index> <newPin> [curPin]\n",
            .{},
        );
        try stdout.flush();
        return;
    }

    // Allow device selection based on an index. Use this together with the
    // manifest example.
    const device_index: usize = try std.fmt.parseInt(usize, argv[1], 0);
    const newPin = argv[2];
    const curPin = if (argv.len >= 4) argv[3] else null;

    // First, obtain a list of available authenticators.
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

    // Now lets get some information about the authenticator.
    // In this case we're going to use a blocking operation that waits for
    // the result.
    var info_state = try (try client.getInfo(device, .{})).await(allocator);
    defer info_state.deinit(allocator);
    // We then have to deserialize the returned CBOR data.
    const info = try info_state.deserializeCbor(client.Info, allocator);
    defer info.deinit(allocator);

    // If the credMgmt option is not present or false, exit.
    if ((info.options.credMgmt == null or !info.options.credMgmt.?) and
        (info.options.credentialMgmtPreview == null or !info.options.credentialMgmtPreview.?))
    {
        std.log.err("The selected device doesn't support credMgmt", .{});
        return;
    }

    if (info.options.clientPin == null) {
        std.log.warn("client PIN not supported by authenticator", .{});
        return;
    }

    // Obtain a shared secret from the authenticator.
    if (info.pinUvAuthProtocols == null) {
        std.log.err("pinUvAuthProtocols list not provided or empty", .{});
        return;
    }

    const pinUvAuthProtocol = info.pinUvAuthProtocols.?[0];

    var shared_secret = try client.getKeyAgreement(
        device,
        pinUvAuthProtocol,
        allocator,
    );

    // Change an existing PIN
    if (info.options.clientPin.?) {
        if (curPin == null) {
            std.log.err("curPin argument required", .{});
            return;
        }

        var cpr = client.changePin(
            device,
            &shared_secret,
            curPin.?,
            newPin,
            allocator,
        ) catch |e| {
            std.log.err("failed to change pin: {any}", .{e});
            return;
        };

        var cp_state = try cpr.await(allocator);
        defer cp_state.deinit(allocator);

        switch (cp_state) {
            .fulfilled => |data| {
                const status_code = data[0];

                if (status_code != 0) {
                    std.log.err("failed to change pin ({d})", .{status_code});
                }
            },
            else => {
                std.log.err("failed to change pin", .{});
                return;
            },
        }
    } else { // set a new PIN
        const spr = client.setPin(
            device,
            &shared_secret,
            newPin,
            allocator,
        ) catch |e| {
            std.log.err("failed to set pin: {any}", .{e});
            return;
        };
        _ = spr;
    }
}
