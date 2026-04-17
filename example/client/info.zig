//! This example shows how to send a 'authenticatorGetInfo' request
//! to a authenticator.
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

    const argv = try init.minimal.args.toSlice(allocator);
    defer allocator.free(argv);

    // Allow device selection based on an index. Use this together with the
    // manifest example.
    var device_index: usize = 0;
    if (argv.len >= 2) {
        device_index = std.fmt.parseInt(usize, argv[1], 0) catch 0;
    }

    // First, obtain a list of available authenticators.
    var transports = try client.Transports.enumerate(
        allocator,
        init.io,
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
    device.open() catch |e| {
        const device_name = device.allocPrint(allocator) catch "";
        defer allocator.free(device_name);

        std.log.err(
            "Failed to open device '{s}' ({any})",
            .{ device_name, e },
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
    //
    // You can define the number of ms until a timeout occurs by setting
    // the `timeout` field of the `opts` struct (second argument).
    var promise = try client.getInfo(device, init.io, .{});

    // All commands return a "Promise", i.e. a data structure
    // that can represent different states. Usually, the initial
    // state is 'pending', meaning the client waits for the
    // authenticator to handle the request, and later switches
    // to 'fulfilled'. On error, the promise state switches to
    // 'rejected'.
    const info = outer: while (true) {
        const state = promise.get(allocator, init.io);
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
                break :outer try state.deserializeCbor(client.Info, allocator);
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
