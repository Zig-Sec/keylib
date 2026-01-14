//! Enumerates all available FIDO authenticators and simultaneously
//! requests user presence (UP) on all of them, printing information
//! about the selected device.
//!
//! TODO: NOT YET TESTED
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");

const client = @import("client");
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const authenticatorSelection = client.cbor_commands.authenticatorSelection;
const Info = client.cbor_commands.Info;

// Allocator to be used for allocating dynamic memory.
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

// Buffered stdout (don't forget to flush!).
var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

pub fn main() !void {
    // First, obtain a list of available authenticators.
    var transports = try client.Transports.enumerate(
        allocator,
        .{},
    );
    defer transports.deinit();

    // Check if there is at least one device available.
    if (transports.devices.len == 0) {
        std.log.err("No device available", .{});
        return;
    }

    var promises: std.ArrayListUnmanaged(client.cbor_commands.Promise) = .empty;
    for (transports.devices) |*device| {
        try device.open();

        try promises.append(
            allocator,
            try authenticatorSelection(device, 30000),
        );
    }

    // We'll loop over the devices and check if one of them has received
    // a user presence.
    //
    // All devices sould timeout afeter roughly 30 seconds.
    var i: usize = 0;
    while (true) {
        defer i += 1;

        if (promises.items.len == 0) break;
        if (i >= promises.items.len) i = 0;

        const promise = &promises.items[i];

        const state = promise.get(allocator);
        defer state.deinit(allocator);

        switch (state) {
            .pending => continue,
            .fulfilled => |d| {
                std.log.info("{d}", .{d[0]});
                break;
            },
            .rejected => {
                _ = promises.swapRemove(i);
                continue;
            },
        }
    }
}
