//! This example shows how create a client that authenticates against a
//! server using `py_webauthn` for creating registration options and
//! response validation.
//!
//! Copyright (c) 2022 - 2026 David P. Sugar.
//! Use of this source code is governed by the MIT license.
const std = @import("std");
const clap = @import("clap");

const client = @import("client");

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
        \\--cmd <str>            "register" or "authenticate"
        \\--url <str>            URL
        \\--username <str>       Username
        \\-p <str>               Specify a PIN for authentication
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

    const url = res.args.url orelse {
        try stdout.print("missing 'url' option\n", .{});
        try stdout.flush();
        return;
    };
    std.log.info("url: {s}", .{url});

    var http_client: std.http.Client = .{
        .allocator = allocator,
        .io = init.io,
    };
    defer http_client.deinit();

    if (res.args.cmd) |cmd| {
        std.log.info("cmd: {s}", .{cmd});

        if (std.mem.eql(u8, cmd, "register")) {
            const username = res.args.username orelse {
                try stdout.print("missing 'username' option\n", .{});
                try stdout.flush();
                return;
            };
            std.log.info("username: {s}", .{username});

            try make_credential(
                allocator,
                init.io,
                &http_client,
                url,
                username,
            );
        } else if (std.mem.eql(u8, cmd, "authenticate")) {} else {
            try stdout.print("valid commands are: \"register\" and \"authenticate\"\n", .{});
            try stdout.flush();
            return;
        }
    } else {
        try stdout.print("missing 'cmd' option\n", .{});
        try stdout.flush();
        return;
    }

    try stdout.flush();
    try stderr.flush();
}

fn make_credential(
    allocator: std.mem.Allocator,
    io: std.Io,
    http_client: *std.http.Client,
    url: []const u8,
    username: []const u8,
) !void {
    _ = io;

    const regdata = RegistrationData{
        .username = username,
    };
    var jregdata = std.Io.Writer.Allocating.init(allocator);
    defer jregdata.deinit();
    try regdata.toJson(&jregdata.writer);
    std.log.info("registration data: {s}", .{jregdata.written()});

    const headers = &[_]std.http.Header{
        .{ .name = "Accept", .value = "application/json" },
        .{ .name = "Content-Type", .value = "application/json" },
    };

    var result_body = std.Io.Writer.Allocating.init(allocator);
    defer result_body.deinit();

    _ = try http_client.fetch(.{
        .location = .{ .url = url },
        .method = .POST,
        .extra_headers = headers,
        .payload = jregdata.written(),
        .response_writer = &result_body.writer,
    });

    std.log.info("response: {s}", .{result_body.written()});
}

const RegistrationData = struct {
    username: []const u8,

    pub fn toJson(self: *const @This(), writer: *std.Io.Writer) !void {
        var fmt = std.json.fmt(
            self,
            .{
                .emit_null_optional_fields = false,
            },
        );

        try fmt.format(writer);
    }
};

const help_text =
    \\usage: py_webauthn_client [options]
    \\
    \\--help                 Display this help and exit.
    \\--cmd <str>            "register" or "authenticate"
    \\--url <str>            URL for registration/ authentication
    \\-p <str>               Specify a PIN for authentication
    \\
;
