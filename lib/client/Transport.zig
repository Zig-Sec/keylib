//! Abstract representation of a USB, NFC, or Bluetooth device

const std = @import("std");
const Self = @This();

pub const Error = error{
    /// Unable to initialize the transport
    Init,
    OutOfMemory,
    Open,
    Read,
    Write,
    Timeout,
    NoChannel,
    InvalidPacketLength,
    InvalidPacket,
    InvalidCid,
    InvalidCmd,
    InvalidPar,
    InvalidLen,
    InvalidSeq,
    MsgTimeout,
    ChannelBusy,
    LockRequired,
    InvalidChannel,
    UnexpectedCommand,
    InvalidSequenceNumber,
    NonceMismatch,
    InvalidSize,
    Processing,
    UpNeeded,
    Canceled,
    EntropyUnavailable,
    Other,
};

/// Type erased pointer to the underlying object (e.g. Usb)
obj: *anyopaque,

_read: *const fn (self: *anyopaque, a: std.mem.Allocator) Error!?[]u8,
_write: *const fn (self: *anyopaque, out: []const u8) Error!void,
_close: *const fn (self: *anyopaque) void,
_open: *const fn (self: *anyopaque) Error!void,
_allocPrint: *const fn (self: *anyopaque, a: std.mem.Allocator) Error![]const u8,
_deinit: *const fn (self: *anyopaque) void,

pub fn read(self: *const Self, a: std.mem.Allocator) Error!?[]u8 {
    return self._read(self.obj, a);
}

pub fn write(self: *Self, out: []const u8) Error!void {
    return self._write(self.obj, out);
}

pub fn close(self: *Self) void {
    return self._close(self.obj);
}

pub fn open(self: *Self) Error!void {
    return self._open(self.obj);
}

pub fn allocPrint(self: *Self, a: std.mem.Allocator) Error![]const u8 {
    return self._allocPrint(self.obj, a);
}

pub fn deinit(self: *Self) void {
    return self._deinit(self.obj);
}
