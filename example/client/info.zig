//! This example shows how to send a 'authenticatorGetInfo' request
//! to a authenticator.
//!
//! Copyright (c) 2022 - 2025 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");

const client = @import("client");
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
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

    // In our case we'll simply choose the first device available.
    if (transports.devices.len == 0) {
        std.log.err("No device available", .{});
        return;
    }

    var device = &transports.devices[0];

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
    // For this example we'll send the 'authenticatorGetInfo'
    // request to obtain information about the selected authenticator.
    // This is usually the first step regardless of what you want to do
    // as the returned data tells us more about the capabilities of the
    // authenticator.
    var promise = try authenticatorGetInfo(device);

    // All commands return a "Promise", i.e. a data structure
    // that can represent different states. Usually, the initial
    // state is 'pending', meaning the client waits for the
    // authenticator to handle the request, and later switches
    // to 'fulfilled'. On error, the promise state switches to
    // 'rejected'.
    const info = outer: while (true) {
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
                break :outer try state.deserializeCbor(Info, allocator);
            },
            .rejected => |e| {
                return e;
            },
        }
    };
    defer info.deinit(allocator);

    // You can now access the 'Info' struct.
    // In this case, we'll just print the struct as Json to stdout.
    try info.printJson(stdout);
    try stdout.flush(); // Don't forget to flush!
}
