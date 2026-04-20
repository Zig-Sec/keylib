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

    var stdin_buffer: [1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(init.io, &stdin_buffer);
    const stdin = &stdin_reader.interface;

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

    const pin = res.args.p orelse {
        try stdout.print("missing 'p' option\n", .{});
        try stdout.flush();
        return;
    };

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
                pin,
                username,
                stdin,
                stdout,
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
    pin: []const u8,
    username: []const u8,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
) !void {
    // First we must request registration options from the server.
    // The options are JSON encoded and align with the options one
    // would pass the `navigator.credentials.create`
    // --------------------------------------------------------------

    const origin = try originFromUrl(url);
    std.log.info("origin: {s}", .{origin});

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

    // Next we have to decode the options send by the server.
    // --------------------------------------------------------------

    const options = try client.web.Create.fromJsonAlloc(
        allocator,
        result_body.written(),
    );
    defer options.deinit(allocator);

    // Next we have to enumerate available authenticators and let the
    // user select one.
    // --------------------------------------------------------------

    var transports = try client.Transports.enumerate(
        allocator,
        io,
        .{},
    );
    defer transports.deinit();

    // Select a FIDO device.
    if (transports.devices.len == 0) {
        // TODO: support endpoint for telling the server that registration
        // has failed at this point (e.g. by providing the nonce).
        std.log.warn("Please connect an authenticator and run again", .{});
        return;
    }

    try stdout.print("Please select an authenticator by ID or type 'exit'\n", .{});
    for (transports.devices, 0..) |*dev, i| {
        const str = try dev.allocPrint(allocator);
        defer allocator.free(str);

        try stdout.print("  [{d}]: {s}\n", .{ i, str });
    }
    try stdout.flush();

    var str = std.Io.Writer.Allocating.init(allocator);
    defer str.deinit();

    _ = try stdin.streamDelimiter(&str.writer, '\n');

    if (std.mem.eql(u8, str.written(), "exit")) {
        // TODO: handle exit
        return;
    }

    const idx = try std.fmt.parseInt(usize, str.written(), 0);

    if (idx >= transports.devices.len) {
        // TODO: handle exit
        std.log.warn("Index '{d}' out of range", .{idx});
        return;
    }

    std.log.info("selected '{d}'", .{idx});

    var device = &transports.devices[idx];

    device.open() catch {
        // We won't deallocate the name as the process is terminated anyway.
        const device_name = device.allocPrint(allocator) catch "";
        defer allocator.free(device_name);

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

    var info_state = try (try client.getInfo(device, io, .{})).await(allocator, io);
    defer info_state.deinit(allocator);
    const info = try info_state.deserializeCbor(client.Info, allocator);
    defer info.deinit(allocator);

    const pinUvAuthProtocol, const token = try client.pinUvAuthToken(
        device,
        allocator,
        io,
        info,
        .{
            .permissions = .{
                .mc = 1,
            },
            .pin = pin,
            .rpId = options.rp.id,
        },
    );
    defer allocator.free(token);

    // ============================================
    // Prepare the data for the request
    // ============================================

    const challenge_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(options.challenge);
    const challenge = try allocator.alloc(u8, challenge_len);
    defer allocator.free(challenge);
    try std.base64.url_safe_no_pad.Decoder.decode(challenge, options.challenge);

    const clientData = try client.clientDataAlloc(
        allocator,
        "webauthn.create",
        challenge,
        origin,
        false,
    );
    defer allocator.free(clientData);
    std.log.info("clientDataJson: {s}", .{clientData});

    // ============================================
    // Make MC request
    // ============================================

    const uid_len = try std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(options.user.id);
    const uid = try allocator.alloc(u8, uid_len);
    defer allocator.free(uid);
    try std.base64.url_safe_no_pad.Decoder.decode(uid, options.user.id);

    const rk: bool = if (options.authenticatorSelection) |as| blk: {
        if (as.requireResidentKey) |rrk| {
            break :blk rrk;
        } else break :blk false;
    } else false;

    // TODO: handle all options more carefully.
    // - what does the authenticator require (e.g., always UV)
    // - what does the RP want
    // - where is the middle ground?

    var promise = try client.makeCredential(
        device,
        token,
        pinUvAuthProtocol,
        clientData,
        allocator,
        io,
        .{
            .rpId = options.rp.id,
            .rpName = options.rp.name,
            .crossOrigin = false,
            .userId = uid,
            .userName = options.user.name,
            .userDisplayName = options.user.displayName,
            .rk = rk,
        },
    );

    const mc_response = outer: while (true) {
        const state = promise.get(allocator, io);
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
                //std.debug.print("response: {x}", .{state.fulfilled});
                break :outer try state.deserializeCbor(
                    client.MakeCredentialResponse,
                    allocator,
                );
            },
            .rejected => |e| {
                return e;
            },
        }
    };
    defer mc_response.deinit(allocator);

    std.log.info("{any}", .{mc_response});
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
/// This is a naiv parser to extract the origin from a url
fn originFromUrl(str: []const u8) ![]const u8 {
    var i: usize = 0;

    if (std.mem.startsWith(u8, str, "http://")) {
        i += 7;
    } else if (std.mem.startsWith(u8, str, "https://")) {
        i += 8;
    } else {
        std.log.err("missing or invalid scheme while parsing '{s}'", .{str});
        return error.Scheme;
    }

    for (str[i..]) |c| {
        switch (c) {
            '0'...'9', 'a'...'z', '.' => {
                i += 1;
            },
            ':' => {
                i += 1;
                break;
            },
            '/' => break,
            else => {
                std.log.err("missing or invalid host while parsing '{s}'", .{str});
                return error.Host;
            },
        }
    }

    if (str[i - 1] == ':') {
        for (str[i..]) |c| {
            switch (c) {
                '0'...'9' => i += 1,
                else => break,
            }
        }
    }

    return str[0..i];
}
