//! This is a template for implementing your own FIDO2 authenticator based on keylib.
//!
//! While this library allows you to implement a authenticator quite
//! easily as seen below you can also just use the data structures and build one
//! from scratch yourself.

const std = @import("std");
const keylib = @import("keylib");
const cbor = @import("zbor");
const uhid = @import("uhid");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

pub fn main() !void {
    //// a static credential to work with
    //try data_set.append(.{
    //    .id = "\xb4\x40\xa4\xed\x80\x92\xe6\x9b\x19\x25\x2d\x25\x84\xc2\xa4\xce\x56\x38\x66\xd6\x4d\xb3\x13\x4e\x48\xd6\x1b\xc2\xb9\x32\xae\x23",
    //    .rp = "trust-anchor.testbed.oidcfed.incubator.geant.org",
    //    .data = "A96269645820B440A4ED8092E69B19252D2584C2A4CE563866D64DB3134E48D61BC2B932AE236475736572A26269644C0C430EFFFF5F5F5F44454D4F646E616D6565657277696E627270A1626964783074727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72676A7369676E5F636F756E740063616C676545733235366B707269766174655F6B657958201BA2453ED863B547C93AE1B2244459F2E403FC8E951B15F458335DFB3C80397467637265617465641B0000018D75C3FDC86C646973636F76657261626C65F56A657874656E73696F6E7382A26565787449644B6372656450726F746563746865787456616C7565581875736572566572696669636174696F6E4F7074696F6E616CA26565787449644569647049646865787456616C7565584168747470733A2F2F74727573742D616E63686F722E746573746265642E6F6964636665642E696E63756261746F722E6765616E742E6F72672F6F6964632F6F702F",
    //});

    // The Auth struct is the most important part of your authenticator. It defines
    // its capabilities and behavior.
    var auth = keylib.ctap.authenticator.Auth{
        // The callbacks are the interface between the authenticator and the rest of the application (see below).
        .callbacks = callbacks,
        // The commands map from a command code to a command function. All functions have the
        // same interface and you can implement your own to extend the authenticator beyond
        // the official spec, e.g. add a command to store passwords.
        //.commands = &.{
        //    .{ .cmd = 0x01, .cb = keylib.ctap.commands.authenticator.authenticatorMakeCredential },
        //    .{ .cmd = 0x02, .cb = keylib.ctap.commands.authenticator.authenticatorGetAssertion },
        //    .{ .cmd = 0x04, .cb = keylib.ctap.commands.authenticator.authenticatorGetInfo },
        //    .{ .cmd = 0x06, .cb = keylib.ctap.commands.authenticator.authenticatorClientPin },
        //    .{ .cmd = 0x0b, .cb = keylib.ctap.commands.authenticator.authenticatorSelection },
        //},
        // The settings are returned by a getInfo request and describe the capabilities
        // of your authenticator. Make sure your configuration is valid based on the
        // CTAP2 spec!
        .settings = .{
            // Those are the FIDO2 spec you support
            .versions = &.{ .FIDO_2_0, .FIDO_2_1 },
            // The extensions are defined as strings which should make it easy to extend
            // the authenticator (in combination with a new command).
            .extensions = &.{ "credProtect", "federationId" },
            // This should be unique for all models of the same authenticator.
            .aaguid = "\x6f\x15\x82\x74\xaa\xb6\x44\x3d\x9b\xcf\x8a\x3f\x69\x29\x7c\x88".*,
            .options = .{
                // We don't support the credential management command. If you want to
                // then you need to implement it yourself and add it to commands and
                // set this flag to true.
                .credMgmt = false,
                // We support discoverable credentials, a.k.a resident keys, a.k.a passkeys
                .rk = true,
                // We support built in user verification (see the callback below)
                .uv = true,
                // This is a platform authenticator even if we use usb for ipc
                .plat = true,
                // We don't support client pin but you could also add the command
                // yourself and set this to false (not initialized) or true (initialized).
                .clientPin = null,
                // We support pinUvAuthToken
                .pinUvAuthToken = true,
                // If you want to enforce alwaysUv you also have to set this to true.
                .alwaysUv = false,
            },
            // The pinUvAuth protocol to support. This library implements V1 and V2.
            .pinUvAuthProtocols = &.{.V2},
            // The transports your authenticator supports.
            .transports = &.{.usb},
            // The algorithms you support.
            .algorithms = &.{.{ .alg = .Es256 }},
            .firmwareVersion = 0xcafe,
            .remainingDiscoverableCredentials = 100,
        },
        // Here we initialize the pinUvAuth token data structure wich handles the generation
        // and management of pinUvAuthTokens.
        .token = keylib.ctap.pinuv.PinUvAuth.v2(std.crypto.random),
        // Here we set the supported algorithm. You can also implement your
        // own and add them here.
        .algorithms = &.{
            keylib.ctap.crypto.algorithms.Es256,
        },
        // A function to get the epoch time as i64.
        .milliTimestamp = std.time.milliTimestamp,
        // A cryptographically secure random number generator
        .random = std.crypto.random,
        // If you don't want to increment the sign counts
        // of credentials (e.g. because you sync them between devices)
        // set this to true.
        .constSignCount = true,
    };
    try auth.init();

    // Here we instantiate a CTAPHID handler.
    var ctaphid = keylib.ctap.transports.ctaphid.authenticator.CtapHid.init(allocator, std.crypto.random);
    defer ctaphid.deinit();

    // We use the uhid module on linux to simulate a USB device. If you use
    // tinyusb or something similar you have to adapt the code.
    var u = try uhid.Uhid.open();
    defer u.close();

    // This is the main loop
    while (true) {
        // We read in usb packets with a size of 64 bytes.
        var buffer: [64]u8 = .{0} ** 64;
        if (u.read(&buffer)) |packet| {
            // Those packets are passed to the CTAPHID handler who assembles
            // them into a CTAPHID message.
            var response = ctaphid.handle(packet);
            // Once a message is complete (or an error has occured) you
            // get a response.
            if (response) |*res| blk: {
                switch (res.cmd) {
                    // Here we check if its a cbor message and if so, pass
                    // it to the handle() function of our authenticator.
                    .cbor => {
                        var out: [7609]u8 = undefined;
                        const r = auth.handle(&out, res.getData());
                        @memcpy(res._data[0..r.len], r);
                        res.len = r.len;
                    },
                    else => {},
                }

                var iter = res.iterator();
                // Here we iterate over the response packets of our authenticator.
                while (iter.next()) |p| {
                    u.write(p) catch {
                        break :blk;
                    };
                }
            }
        }
        std.time.sleep(10000000);
    }
}

// /////////////////////////////////////////
// Data
// /////////////////////////////////////////

// For this example we use a volatile storage solution for our credentials.
var data_set = std.ArrayList(Credential).init(allocator);
var fetch_index: ?usize = null;
var fetch_id: ?[]const u8 = null;
var fetch_rp: ?[]const u8 = null;

// /////////////////////////////////////////
// Auth
//
// Below you can see all the callbacks you have to implement
// (that are expected by the default command functions). Make
// sure you allocate memory with the same allocator that you
// passed to the Auth sturct.
//
// How you check user presence, conduct user verification or
// store the credentials is up to you.
// /////////////////////////////////////////

const UpResult = keylib.ctap.authenticator.callbacks.UpResult;
const UvResult = keylib.ctap.authenticator.callbacks.UvResult;
const Error = keylib.ctap.authenticator.callbacks.Error;
const Credential = keylib.ctap.authenticator.Credential;
const CallbackError = keylib.ctap.authenticator.callbacks.CallbackError;
const Meta = keylib.ctap.authenticator.Meta;

pub fn my_uv(
    /// Information about the context (e.g., make credential)
    info: []const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: ?keylib.common.User,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: ?keylib.common.RelyingParty,
) UvResult {
    _ = info;
    _ = user;
    _ = rp;
    // The authenticator backend is only started if a correct password has been provided
    // so we return Accepted. As this state may last for multiple minutes it's important
    // that we ask for user presence, i.e. we DONT return AcceptedWithUp!
    //
    // TODO: "logout after being inactive for m minutes"
    return UvResult.Accepted;
}

pub fn my_up(
    /// Information about the context (e.g., make credential)
    info: []const u8,
    /// Information about the user (e.g., `David Sugar (david@example.com)`)
    user: ?keylib.common.User,
    /// Information about the relying party (e.g., `Github (github.com)`)
    rp: ?keylib.common.RelyingParty,
) UpResult {
    _ = info;
    _ = user;
    _ = rp;

    return UpResult.Accepted;
}

pub fn my_read_first(
    id: ?[]const u8,
    rp: ?[]const u8,
) CallbackError!Credential {
    std.log.info("my_first_read: {any}, {any}", .{ id, rp });

    if (id != null) {
        fetch_id = id;
        fetch_index = 0;

        while (fetch_index.? < data_set.items.len) : (fetch_index.? += 1) {
            if (std.mem.eql(u8, data_set.items[fetch_index.?].id.get(), id.?)) {
                const v = data_set.items[fetch_index.?];
                fetch_index.? += 1;
                if (fetch_index.? >= data_set.items.len) {
                    fetch_id = null;
                    fetch_index = null;
                }
                return v;
            }
        }

        return error.DoesNotExist;
    } else if (rp != null) {
        fetch_rp = rp;
        fetch_index = 0;

        while (fetch_index.? < data_set.items.len) : (fetch_index.? += 1) {
            if (std.mem.eql(u8, data_set.items[fetch_index.?].rp.id.get(), rp.?)) {
                const v = data_set.items[fetch_index.?];
                fetch_index.? += 1;
                if (fetch_index.? >= data_set.items.len) {
                    fetch_rp = null;
                    fetch_index = null;
                }
                return v;
            }
        }

        return error.DoesNotExist;
    } else {
        fetch_index = 0;

        if (fetch_index.? < data_set.items.len) {
            const v = data_set.items[fetch_index.?];
            fetch_index.? += 1;
            if (fetch_index.? >= data_set.items.len) {
                fetch_index = null;
            }
            return v;
        } else {
            fetch_index = null;
        }

        return error.DoesNotExist;
    }

    return error.DoesNotExist;
}

pub fn my_read_next() CallbackError!Credential {
    std.log.info("my_read_next: {any}, {any}, {any}", .{ fetch_index, fetch_id, fetch_rp });

    if (fetch_index != null) {
        std.log.info("my_read_next: fetch index not null", .{});
        if (fetch_index.? >= data_set.items.len) {
            fetch_index = null;
            fetch_id = null;
            fetch_rp = null;
            return error.DoesNotExist;
        }

        if (fetch_id) |id| {
            while (fetch_index.? < data_set.items.len) : (fetch_index.? += 1) {
                if (std.mem.eql(u8, data_set.items[fetch_index.?].id.get(), id)) {
                    const v = data_set.items[fetch_index.?];
                    fetch_index.? += 1;
                    if (fetch_index.? >= data_set.items.len) {
                        fetch_id = null;
                        fetch_index = null;
                    }
                    return v;
                }
            }
            return error.DoesNotExist;
        }

        if (fetch_rp) |id| {
            while (fetch_index.? < data_set.items.len) : (fetch_index.? += 1) {
                if (std.mem.eql(u8, data_set.items[fetch_index.?].rp.id.get(), id)) {
                    const v = data_set.items[fetch_index.?];
                    fetch_index.? += 1;
                    if (fetch_index.? >= data_set.items.len) {
                        fetch_rp = null;
                        fetch_index = null;
                    }
                    return v;
                }
            }
            return error.DoesNotExist;
        }
    }

    std.log.info("my_read_next: throw error", .{});
    return error.DoesNotExist;
}

pub fn my_write(
    data: Credential,
) CallbackError!void {
    var i: usize = 0;

    while (i < data_set.items.len) : (i += 1) {
        if (std.mem.eql(u8, data_set.items[i].id.get(), data.id.get())) {
            data_set.items[i] = data;
            return;
        }
    }

    try data_set.append(data);
}

pub fn my_delete(
    id: [*c]const u8,
) callconv(.C) Error {
    _ = id;
    return Error.Other;
}

pub fn my_read_settings() Meta {
    return Meta{};
}

pub fn my_write_settings(data: Meta) void {
    _ = data;
}

const callbacks = keylib.ctap.authenticator.callbacks.Callbacks{
    .up = my_up,
    .uv = my_uv,
    .read_first = my_read_first,
    .read_next = my_read_next,
    .write = my_write,
    .delete = my_delete,
    .read_settings = my_read_settings,
    .write_settings = my_write_settings,
};

// MISC

pub fn strlen(s: [*c]const u8) usize {
    var i: usize = 0;
    while (s[i] != 0) : (i += 1) {}
    return i;
}
