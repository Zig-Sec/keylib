const std = @import("std");
const client = @import("client");
const authenticatorGetInfo = client.cbor_commands.authenticatorGetInfo;
const client_pin = client.cbor_commands.client_pin;
const cred_management = client.cbor_commands.cred_management;
const Info = client.cbor_commands.Info;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var allocator = gpa.allocator();

var stdout_buffer: [1024]u8 = undefined;
var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
const stdout = &stdout_writer.interface;

pub fn main() !void {
    const pw = if (std.os.argv.len >= 2) blk: {
        var i: usize = 0;
        while (std.os.argv[1][i] != 0) : (i += 1) {}
        break :blk std.os.argv[1][0..i];
    } else {
        std.log.err("please provide a password", .{});
        return;
    };

    {
        // 1 The platform examines various option IDs in the authenti-
        //   catorGetInfo response to determine its course of action

        // Get all devices connect to the platform
        var transports = try client.Transports.enumerate(allocator, .{});
        defer transports.deinit();

        // Choose a device
        if (transports.devices.len == 0) {
            std.log.err("No device found, exiting...", .{});
            return;
        }

        var device = if (transports.devices.len == 1) blk: {
            break :blk &transports.devices[0];
        } else blk: {
            std.log.info("Please choose a device from the following list:", .{});
            for (transports.devices, 0..) |*device, i| {
                const x = try device.allocPrint(allocator);
                defer allocator.free(x);
                std.log.info("  {d} {s}", .{ i, x });
            }
            // Here we would actually ask for some user input but
            // let's keep it simple...
            break :blk &transports.devices[0];
        };

        // Open a connection to the device
        try device.open();
        defer device.close();

        // Get information about the device and its capabilities
        const infos = try (try authenticatorGetInfo(device)).await(allocator);
        defer infos.deinit(allocator);
        const info = try infos.deserializeCbor(Info, allocator);
        defer info.deinit(allocator);
        try info.printJson(stdout);
        try stdout.flush();
        //std.log.info("info: {any}", .{info});

        // 1.a If the credMgmt option is not present or false, exit and
        //     fall back to manual selection.
        if ((info.options.credMgmt == null or !info.options.credMgmt.?) and
            (info.options.credentialMgmtPreview == null or !info.options.credentialMgmtPreview.?))
        {
            std.log.err("The selected device doesn't support credMgmt", .{});
            return;
        }

        // 1.b if both clientPin and uv option are either absent or false

        if (info.options.clientPin == null and info.options.uv == null) {
            std.log.err("The selected device doesn't support user verification", .{});
            return;
        }

        if (!info.options.clientPin.? and !info.options.uv.?) {
            std.log.err("No user verification set up for device", .{});
            return;
        }

        // 1.c if the uv option ID is present and set to true:
        var op: ?[]const u8 = null;

        // We prefer internal uv over pin
        if (info.options.uv != null and info.options.uv.?) {
            if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                op = "getPinUvAuthTokenUsingUvWithPermissions";
            }
        }

        if (op == null) {
            if (info.options.pinUvAuthToken != null and info.options.pinUvAuthToken.?) {
                if (info.options.clientPin != null and info.options.clientPin.?) {
                    op = "getPinUvAuthTokenUsingPinWithPermissions";
                }
            } else {
                if (info.options.clientPin != null and info.options.clientPin.?) {
                    op = "getPinToken";
                }
            }
        }

        if (op == null) {
            std.log.err("Selected authenticator doesn't support pinUvAuthToken", .{});
            return;
        }

        // 2 In preparation for obtaining pinUvAuthToken, the platform:

        // 2.a Obtains a shared secret

        if (info.pinUvAuthProtocols == null) {
            std.log.err("Device supports user verification but no pinUvAuthProtocols were returned as a result of calling getInfo", .{});
            return;
        }

        const pinUvAuthProtocol = info.pinUvAuthProtocols.?[0];

        var enc = try client_pin.getKeyAgreement(device, pinUvAuthProtocol, allocator);
        std.log.info("shared secret: {any}", .{enc});

        // 3 Optain a pinUvAuthToken from the authenticator

        const token = if (std.mem.eql(u8, op.?, "getPinToken")) blk: {
            break :blk try client_pin.getPinToken(device, &enc, pw[0..], allocator);
        } else if (std.mem.eql(u8, op.?, "getPinUvAuthTokenUsingUvWithPermissions")) blk: {
            break :blk ""; // here we would return a token generated via getPinUvAuthTokenUsingUvWithPermissions
        } else blk: {
            break :blk ""; // here we would return a token generated via getPinUvAuthTokenUsingPinWithPermissions
        };
        defer allocator.free(token);
        std.log.info("token: {x}", .{token});

        // 4 the platform collects all RPs present on the given authenticator, removes RPs that
        //   are not supported IdPs, and then selects the IdP for authentication

        // 4.a Create a empty set of idps
        var idps: std.ArrayList([]const u8) = .empty;
        defer {
            for (idps.items) |idp| {
                allocator.free(idp);
            }
        }

        // 4.b Fill the set with RPs present on the authenticator
        const rp = try cred_management.enumerateRPsBegin(device, pinUvAuthProtocol, token, allocator, true);
        if (rp) |_rp| {
            try idps.append(allocator, try allocator.dupe(u8, _rp.rp.id.get()));

            var i: usize = 0;
            while (i < _rp.total.? - 1) : (i += 1) {
                if (try cred_management.enumerateRPsGetNextRP(device, allocator, true)) |rp2| {
                    try idps.append(allocator, try allocator.dupe(u8, rp2.rp.id.get()));
                }
            }
        } else {
            std.log.info("no valid RPs found", .{});
            return;
        }

        // 4.c Remove all RPs that are not valid IdPs
        var i: usize = 0;
        while (true) {
            if (i >= idps.items.len) break;
            if (!std.mem.eql(u8, "github.com", idps.items[i])) {
                // The only valid IdP in our case is github.com
                const s = idps.swapRemove(i);
                allocator.free(s);
            } else {
                i += 1;
            }
        }

        if (idps.items.len == 0) {
            std.log.info("no valid RPs found", .{});
            return;
        }

        std.log.info("IdPs found:", .{});
        for (idps.items) |idp| {
            std.log.info("    {s}", .{idp});
        }

        const uri = try std.fmt.allocPrint(allocator, "https://{s}", .{idps.items[0]});
        defer allocator.free(uri);

        // 5 if there has been a identity provider selected, authenticate
        //   through the selected IdP

        var promise = try client.cbor_commands.credentials.get(
            device,
            uri,
            false,
            .{
                .rpId = idps.items[0],
                .challenge = "\x01\x23\x45\x67\x89\xab",
            },
            .{
                .param = token,
                .protocol = pinUvAuthProtocol,
            },
            allocator,
        );

        while (true) {
            const S = promise.get(allocator);
            defer S.deinit(allocator);

            switch (S) {
                .pending => |p| {
                    switch (p) {
                        .processing => std.log.info("processing", .{}),
                        .user_presence => std.log.info("user presence", .{}),
                        .waiting => std.log.info("waiting", .{}),
                    }
                },
                .fulfilled => |d| {
                    std.log.info("{x}", .{d});
                    break;
                },
                .rejected => |e| {
                    return e;
                },
            }
        }
    }

    //if (gpa.detectLeaks()) {
    //    std.log.info("leak", .{});
    //}
}
