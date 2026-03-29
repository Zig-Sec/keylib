//! Prints a list of available FIDO devices.
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

    // First, obtain a list of available authenticators.
    var transports = try client.Transports.enumerate(
        allocator,
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
