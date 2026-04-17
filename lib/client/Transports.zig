//! A collection of Transport's
//!
//! Each Transport is the abstract representation of a (authenticator) device
//! you can communicate with.

const std = @import("std");

pub const Transport = @import("Transport.zig");
pub const usb = @import("transports/usb.zig");

pub const Error = error{
    OutOfMemory,
};

pub const EnumerateOptions = struct {
    funs: []const *const fn (a: std.mem.Allocator, io: std.Io) Error!?[]Transport = &.{
        usb.enumerate,
    },
};

const Self = @This();

devices: []Transport,
allocator: std.mem.Allocator,

pub fn deinit(self: *const Self) void {
    for (self.devices) |*dev| {
        dev.deinit();
    }
    self.allocator.free(self.devices);
}

/// Find all connected devices
pub fn enumerate(a: std.mem.Allocator, io: std.Io, options: EnumerateOptions) Error!Self {
    var arr: std.ArrayListUnmanaged(Transport) = .empty;
    errdefer arr.deinit(a);

    for (options.funs) |fun| {
        if (try fun(a, io)) |v| {
            defer a.free(v);

            try arr.appendSlice(a, v);
        }
    }

    const s = try arr.toOwnedSlice(a);

    return Self{
        .devices = s,
        .allocator = a,
    };
}
