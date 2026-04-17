//! Usb transport implementation for FIDO2/ PassKey authenticator
//!
//! This implementation allows you to interact with a authenticator over USB,
//! using the CTAPHID protocol.
const std = @import("std");

const hidapi = @cImport({
    @cInclude("hidapi.h");
});

const Transport = @import("../Transport.zig");
const Transports = @import("../Transports.zig");
const ctaphid = @import("ctaphid/ctaphid.zig");

var initialized: bool = false;

/// Abstract representation of a USB connection
pub const Usb = struct {
    path: [:0]const u8,
    manufacturer: []const u8,
    product: []const u8,
    device: ?*hidapi.hid_device = null,
    channel: ?ctaphid.InitResponse = null,
    allocator: std.mem.Allocator,
    io: std.Io,

    /// Deinitialize the given USB connection
    ///
    /// Calling this function will free all allocated memory, including
    /// the pointer to self! It will also close any open USB connection.
    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.path);
        self.allocator.free(self.manufacturer);
        self.allocator.free(self.product);
        self.close();
        self.allocator.destroy(self);
    }

    /// Establish a USB connection with the device pointed to by `path`
    pub fn open(self: *@This()) Transport.Error!void {
        const dev = hidapi.hid_open_path(self.path.ptr);
        if (dev == null) return error.Open;
        self.device = dev;
        _ = hidapi.hid_set_nonblocking(self.device.?, 1);
        ctaphid.init(self) catch return error.Init;
    }

    /// Close the USB connection
    pub fn close(self: *@This()) void {
        if (self.device != null) {
            hidapi.hid_close(self.device.?);
            self.device = null;
        }
    }

    /// Write a single USB packet to the device
    pub fn write(self: *@This(), out: [64]u8) Transport.Error!void {
        // first byte is the report number
        var o: [65]u8 = .{0} ** 65;
        @memcpy(o[1..], out[0..]);

        // Open the device if not already done
        if (self.device == null) {
            try self.open();
        }

        if (hidapi.hid_write(self.device.?, o[0..].ptr, 65) < 0) {
            return error.Write;
        }
    }

    /// Read a single USB packet from the device
    pub fn read(self: *@This(), out: *[64]u8, cid: u32) Transport.Error!usize {
        var x: [65]u8 = .{0} ** 65;

        // Open the device if not already done
        if (self.device == null) {
            try self.open();
        }

        const res = hidapi.hid_read(self.device.?, x[0..64].ptr, 64);
        if (res < 0) {
            return error.Read;
        } else if (res == 0) {
            return 0;
        }

        const r: usize = @intCast(res);
        // TODO: fix this
        // We determine if the first byte is the endpoint number by comparing
        // the first byte of the expected cid with the first byte of the packet.
        var offset: usize = if (x[0] != @as(u8, @intCast(cid & 0xff))) 1 else 0;
        offset = 0;

        //std.log.info("{s}", .{std.fmt.fmtSliceHexLower(x[0..r])});
        @memcpy(out[0 .. r - offset], x[offset..r]);
        return r;
    }
};

inline fn init() Transport.Error!void {
    if (!initialized) {
        if (hidapi.hid_init() < 0) {
            return error.Init;
        }
        initialized = true;
    }
}

/// Make sure to handle error.Processing and error.UpNeeded as those MUST NOT end the transaction!
pub fn read(self: *anyopaque, a: std.mem.Allocator) Transport.Error!?[]u8 {
    try init();
    const usb: *Usb = @ptrCast(@alignCast(self));
    return ctaphid.cbor_read(usb, a) catch |e| {
        if (e == error.Timeout) return null else return e;
    };
}

pub fn write(self: *anyopaque, data: []const u8) Transport.Error!void {
    try init();
    const usb: *Usb = @ptrCast(@alignCast(self));
    try ctaphid.cbor_write(usb, data);
}

pub fn close(self: *anyopaque) void {
    const usb: *Usb = @ptrCast(@alignCast(self));
    usb.close();
}

pub fn open(self: *anyopaque) Transport.Error!void {
    try init();
    const usb: *Usb = @ptrCast(@alignCast(self));
    try usb.open();
}

pub fn deinit(self: *anyopaque) void {
    const usb: *Usb = @ptrCast(@alignCast(self));
    usb.deinit();
}

pub fn allocPrint(self: *anyopaque, a: std.mem.Allocator) Transport.Error![]const u8 {
    const usb: *Usb = @ptrCast(@alignCast(self));
    return try std.fmt.allocPrint(a, "{s}: {s} {s}", .{ usb.path, usb.manufacturer, usb.product });
}

/// Enumerate all connected USB devices and return those as Transport's that might be a authenticator
pub fn enumerate(a: std.mem.Allocator, io: std.Io) Transports.Error!?[]Transport {
    var devices = hidapi.hid_enumerate(0, 0);
    defer hidapi.hid_free_enumeration(devices);

    if (devices == null) return null;

    var arr: std.ArrayList(Transport) = .empty;
    defer arr.deinit(a);

    while (true) {
        if (devices.*.usage_page == 0xf1d0 and devices.*.usage == 0x01) {
            const u = try a.create(Usb);
            u.* = Usb{
                .path = try a.dupeZ(u8, to_str(devices.*.path)),
                .manufacturer = try a.dupe(u8, wchar_t_to_str(devices.*.manufacturer_string)),
                .product = try a.dupe(u8, wchar_t_to_str(devices.*.product_string)),
                .allocator = a,
                .io = io,
            };

            const t = Transport{
                .obj = @ptrCast(u),
                ._read = read,
                ._write = write,
                ._open = open,
                ._close = close,
                ._allocPrint = allocPrint,
                ._deinit = deinit,
            };

            arr.append(a, t) catch {
                return null;
            };
        }
        if (devices.*.next == null) break;
        devices = devices.*.next;
    }

    return arr.toOwnedSlice(a) catch {
        return null;
    };
}

fn wchar_t_to_str(in: [*c]hidapi.wchar_t) []const u8 {
    var i: usize = 0;
    while (in[i] != 0) : (i += 1) {}
    return std.mem.sliceAsBytes(in[0..i]);
}

fn to_str(in: [*c]u8) []const u8 {
    var i: usize = 0;
    while (in[i] != 0) : (i += 1) {}
    return in[0..i];
}
