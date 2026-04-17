//! Client side CTAPHID protocol implementation

const std = @import("std");

const keylib = @import("keylib");
const ctaphid = keylib.ctap.transports.ctaphid;
const Cmd = ctaphid.Cmd;
const ErrorCodes = ctaphid.authenticator.ErrorCodes;
pub const InitResponse = ctaphid.authenticator.InitResponse;
const CtapHidMessageIterator = ctaphid.message.CtapHidMessageIterator;
const sliceToInt = keylib.ctap.transports.ctaphid.authenticator.misc.sliceToInt;

const DEFAULT_TIMEOUT_MS = 500;

const Usb = @import("../usb.zig").Usb;

pub fn init(usb: *Usb) !void {
    var nonce: [8]u8 = undefined;
    try usb.io.randomSecure(nonce[0..]);

    var request = CtapHidMessageIterator.new(0xffffffff, Cmd.init);
    request.data = nonce[0..];

    try usb.write(request.next().?[0..64].*);

    const response = try ctaphid_read(usb, Cmd.init, 0xffffffff, DEFAULT_TIMEOUT_MS, usb.allocator);
    defer usb.allocator.free(response);

    if (!std.mem.eql(u8, nonce[0..], response[0..8])) return error.NonceMismatch;

    //std.log.info("init: {s}", .{std.fmt.fmtSliceHexLower(response)});

    usb.channel = try InitResponse.deserialize(response);

    //std.log.info("init: {any}", .{usb.channel.?});
}

pub fn cbor_write(usb: *Usb, cbor_data: []const u8) !void {
    if (usb.channel == null) {
        try init(usb);
    }

    var request = CtapHidMessageIterator.new(usb.channel.?.cid, Cmd.cbor);
    request.data = cbor_data;

    while (request.next()) |d| {
        try usb.write(d[0..64].*);
    }
}

pub fn cbor_read(usb: *Usb, a: std.mem.Allocator) ![]u8 {
    if (usb.channel == null) return error.NoChannel;

    const response = try ctaphid_read(usb, Cmd.cbor, usb.channel.?.cid, DEFAULT_TIMEOUT_MS, a);

    //std.log.info("cbor: {s}", .{std.fmt.fmtSliceHexLower(response)});

    return response;
}

pub fn ctaphid_read(usb: *Usb, cmd: Cmd, cid: u32, tout_ms: i64, a: std.mem.Allocator) ![]u8 {
    var expected: ?usize = null;
    var total: usize = 0;
    var seq: i16 = -1;
    var data: [7609]u8 = undefined;

    const start = std.Io.Timestamp.now(usb.io, .real);

    while (true) {
        if (start.untilNow(usb.io, .real).toMilliseconds() > tout_ms) return error.Timeout;

        var buffer: [64]u8 = undefined;
        const l = try usb.read(&buffer, cid);

        if (l > 0) {
            if (seq == -1) {
                if (l < 7) return error.InvalidPacketLength;
                if (buffer[4] & 0x80 == 0) return error.InvalidPacket;
                const _cid = sliceToInt(u32, buffer[0..4]);
                if (_cid != cid) return error.InvalidCid;
                const _cmd = @as(Cmd, @enumFromInt(buffer[4] & 0x7f));
                if (_cmd != cmd) {
                    if (_cmd == Cmd.err) {
                        return switch (buffer[7]) {
                            0x01 => error.InvalidCmd,
                            0x02 => error.InvalidPar,
                            0x03 => error.InvalidLen,
                            0x04 => error.InvalidSeq,
                            0x05 => error.MsgTimeout,
                            0x06 => error.ChannelBusy,
                            0x0a => error.LockRequired,
                            0x0b => error.InvalidChannel,
                            else => error.Other,
                        };
                    } else if (_cmd == Cmd.keepalive) {
                        // A Keepalive is not considered a response and doesnt end a transaction!
                        // The calling function has to check for this error and handle it
                        // by calling ctaphid_read again!
                        return switch (buffer[7]) {
                            0x01 => error.Processing,
                            0x02 => error.UpNeeded,
                            else => error.Other,
                        };
                    } else {
                        return error.UnexpectedCommand;
                    }
                }
                expected = (@as(usize, @intCast(buffer[5])) << 8) + @as(usize, @intCast(buffer[6]));

                const size = l - 7;
                @memcpy(data[0..size], buffer[7..l]);
                total += @intCast(size);
                seq += 1;
            } else {
                if (l < 5) return error.InvalidPacketLength;
                if (buffer[4] & 0x80 != 0) return error.InvalidPacket;
                if (buffer[4] != seq) return error.InvalidSequenceNumber;

                const size = l - 5;
                @memcpy(data[total .. total + size], buffer[5..l]);
                total += @intCast(size);
                seq += 1;
            }
        }

        if (expected != null and total >= expected.?) {
            const o = try a.alloc(u8, expected.?);
            @memcpy(o, data[0..expected.?]);
            return o;
        }
    }
}
