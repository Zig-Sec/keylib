//! Copyright (c) 2022 - 2026 David P. Sugar.
//! Use of this source code is governed by the MIT license.

const std = @import("std");
const clap = @import("clap");

const client = @import("client");
const cbor = @import("zbor");

pub fn main(init: std.process.Init) !void {

    // Allocator to be used for allocating dynamic memory.
    var gpa = std.heap.DebugAllocator(.{}){};
    const allocator = gpa.allocator();

    defer _ = gpa.detectLeaks();

    // Buffered stdout (don't forget to flush!).
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buffer);
    const stderr = &stderr_writer.interface;

    const params = comptime clap.parseParamsComptime(
        \\--help                 Display this help and exit.
        \\<str>                  Hex encoded make credential (mc) response 
        \\
    );

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, init.minimal.args, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(stderr, err) catch {};
        try stderr.flush();
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try stdout.print("{s}", .{help_text});
        try stdout.flush();
        return;
    }

    const attestation_object_hex = if (res.positionals[0]) |v| v else {
        try stderr.print("missing attestationObject", .{});
        try stderr.flush();
        return;
    };

    var ao_buffer: [1024 * 8]u8 = undefined;
    const attestation_object = std.fmt.hexToBytes(&ao_buffer, attestation_object_hex) catch |e| {
        try stderr.print("unable to parse hex-string ({any})", .{e});
        try stderr.flush();
        return;
    };

    const di = cbor.DataItem.new(attestation_object) catch |e| {
        try stderr.print("malformed CBOR data item '{x}' ({any})", .{
            attestation_object,
            e,
        });
        try stderr.flush();
        return;
    };
    const decoded_attestation_object = cbor.parse(
        client.MakeCredentialResponse,
        di,
        .{ .allocator = allocator },
    ) catch |e| {
        try stderr.print("unable to parse attestationObject ({any})", .{e});
        try stderr.flush();
        return;
    };
    defer decoded_attestation_object.deinit(allocator);

    if (decoded_attestation_object.authData.extensions) |extensions| {
        std.debug.print("{any}\n", .{extensions});
    }

    try stdout.flush();
    try stderr.flush();
}

const help_text = "help";
