//! Prints a list of available FIDO devices.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");

const client = @import("client");

// Allocator to be used for allocating dynamic memory.
var gpa = std.heap.DebugAllocator(.{}){};
var allocator = gpa.allocator();

pub fn main(init: std.process.Init) !void {
    defer _ = gpa.detectLeaks();

    // Buffered stdout (don't forget to flush!).
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    // First, obtain a list of available authenticators.
    var transports = try client.Transports.enumerate(
        allocator,
        init.io,
        .{},
    );
    defer transports.deinit();

    // Iterate over all available transports.
    for (transports.devices, 0..) |*device, i| {
        // You can get the descriptor of the device using 'allocPrint'.
        const device_name = try device.allocPrint(allocator);
        defer allocator.free(device_name);

        try stdout.print("[{d}]: {s}\n", .{ i, device_name });
        try stdout.flush(); // Don't forget to flush!
    }
}
