//! This example shows how to reset and authenticator.
//! to a authenticator.
//!
//! Copyright (c) 2022 - 2026 David P. Sugar.
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

    if (argv.len < 2) {
        try stdout.print("usage: reset <device>\n", .{});
        try stdout.flush();
        return;
    }

    const device_index: usize = try std.fmt.parseInt(usize, argv[1], 0);

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

    // After we have opened the device, we can now send requests.
    // For this example we'll send the 'authenticatorReset'
    // request to reset the authenticator.
    //
    // This should be done within the first 10 seconds of powering
    // the authenticator and is a destructive operation.
    var promise = try client.reset(device, 10000);

    // All commands return a "Promise", i.e. a data structure
    // that can represent different states. Usually, the initial
    // state is 'pending', meaning the client waits for the
    // authenticator to handle the request, and later switches
    // to 'fulfilled'. On error, the promise state switches to
    // 'rejected'.
    while (true) {
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
                break;
            },
            .rejected => |e| {
                std.log.err("{any}", .{e});
                break;
            },
        }
    }
}
