//! This module provides functions for dealing with CTAP messages framed
//! for USB transport using the HID (Human Interface Device) protocol (CTAPHID).
//!
//! The communication between a client and the authenticator can be defined in
//! terms of transactions, which consist of a request message issued by a client,
//! followed by a response message.
//!
//! Each message consists of one or more packets with a maximum size s
//! (usually 64 Bytes for full speed usb). The first packet send is always
//! a initialization packet followed by zero or more continuation packets.
//! (see https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb-message-and-packet-structure)

const std = @import("std");
const Allocator = std.mem.Allocator;

const command = @import("Cmd.zig");
pub const Cmd = command.Cmd;
pub const CMD_LENGTH = command.CMD_LENGTH;

pub const misc = @import("misc.zig");
pub const Cid = misc.Cid;
pub const Nonce = misc.Nonce;
pub const CID_LENGTH = misc.CID_LENGTH;
pub const NONCE_LENGTH = misc.NONCE_LENGTH;
pub const BCNT_LENGTH = misc.BCNT_LENGTH;

const resp = @import("message.zig");
pub const CtapHidMessageIterator = resp.CtapHidMessageIterator;

pub const INIT_DATA_LENGTH: u16 = @sizeOf(InitResponse);

/// Supported error codes by the CTAPHID_ERROR response.
pub const ErrorCodes = enum(u8) {
    /// The command in the request is invalid.
    invalid_cmd = 0x01,
    /// The parameters in the request are invalid.
    invalid_par = 0x02,
    /// The length field (BCNT) is invalid for the request.
    invalid_len = 0x03,
    /// The sequence does not match the expected value.
    invalid_seq = 0x04,
    /// The message has timed out,
    msg_timeout = 0x05,
    /// The device is busy for the requesting channel.
    channel_busy = 0x06,
    /// Command requires channel lock.
    lock_required = 0x0a,
    /// CID is not valid.
    invalid_channel = 0x0b,
    /// Unspecified error.
    other = 0x7f,
};

//--------------------------------------------------------------------+
// INIT
//--------------------------------------------------------------------+

/// The response data of a INIT request.
pub const InitResponse = packed struct {
    /// The nonce send with the client request.
    nonce: Nonce,
    /// The allocated 4 byte channel id.
    cid: Cid,
    /// CTAPHID protocol version is 2.
    version_identifier: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    major_device_version_number: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    minor_device_version_number: u8,
    /// The meaning and interpretation of the device version number is vendor defined.
    build_device_version_number: u8,
    /// If set to 1, authenticator implements CTAPHID_WINK function.
    wink: bool,
    /// Reserved for future use (must be set to 0).
    reserved1: bool = false,
    /// If set to 1, authenticator implements CTAPHID_CBOR function.
    cbor: bool,
    /// If set to 1, authenticator DOES NOT implement CTAPHID_MSG function.
    nmsg: bool,
    /// Reserved for future use (must be set to 0).
    reserved2: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved3: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved4: bool = false,
    /// Reserved for future use (must be set to 0).
    reserved5: bool = false,

    pub fn new(nonce: Nonce, cid: Cid, wink: bool, cbor: bool, nmsg: bool) @This() {
        return @This(){
            .nonce = nonce,
            .cid = cid,
            .version_identifier = 2,
            .major_device_version_number = 0xca,
            .minor_device_version_number = 0xfe,
            .build_device_version_number = 0x01,
            .wink = wink,
            .reserved1 = false,
            .cbor = cbor,
            .nmsg = nmsg,
            .reserved2 = false,
            .reserved3 = false,
            .reserved4 = false,
            .reserved5 = false,
        };
    }

    pub fn serialize(self: *const @This(), slice: []u8) void {
        misc.intToSlice(slice[0..NONCE_LENGTH], self.nonce);
        misc.intToSlice(slice[COFF .. COFF + CID_LENGTH], self.cid);
        slice[VIOFF] = self.version_identifier;
        slice[MJDOFF] = self.major_device_version_number;
        slice[MIDOFF] = self.minor_device_version_number;
        slice[BDOFF] = self.build_device_version_number;
        slice[FOFF] = (@as(u8, @intCast(@intFromBool(self.nmsg))) << 3) + (@as(u8, @intCast(@intFromBool(self.cbor))) << 2) + (@as(u8, @intCast(@intFromBool(self.wink))));
    }

    pub fn deserialize(slice: []const u8) !@This() {
        if (slice.len != 17) return error.InvalidSize;

        return .{
            .nonce = misc.sliceToInt(Nonce, slice[0..8]),
            .cid = misc.sliceToInt(u32, slice[8..12]),
            .version_identifier = slice[12],
            .major_device_version_number = slice[13],
            .minor_device_version_number = slice[14],
            .build_device_version_number = slice[15],
            .wink = if (slice[16] & 1 == 1) true else false,
            .cbor = if (slice[16] & 4 == 4) true else false,
            .nmsg = if (slice[16] & 8 == 8) true else false,
        };
    }

    const NOFF: usize = 0;
    const COFF: usize = @sizeOf(Nonce);
    const VIOFF: usize = COFF + @sizeOf(Cid);
    const MJDOFF: usize = VIOFF + 1;
    const MIDOFF: usize = MJDOFF + 1;
    const BDOFF: usize = MIDOFF + 1;
    const FOFF: usize = BDOFF + 1;

    pub const SIZE: usize = FOFF + 1;
};

//--------------------------------------------------------------------+
// message Handler
//--------------------------------------------------------------------+

pub const MAX_DATA_SIZE = 7609;

pub const CtapHidMsg = struct {
    cmd: Cmd,
    cid: Cid,
    _data: [MAX_DATA_SIZE]u8,
    len: usize,

    pub fn new(cmd: Cmd, cid: Cid, data: []const u8) @This() {
        var self: @This() = undefined;
        self.cmd = cmd;
        self.cid = cid;
        @memcpy(self._data[0..data.len], data);
        self.len = data.len;
        return self;
    }

    pub fn getData(self: *const @This()) []const u8 {
        return self._data[0..self.len];
    }

    pub fn iterator(self: *const @This()) CtapHidMessageIterator {
        return resp.iterator(self.cid, self.cmd, self.getData());
    }
};

pub const CtapHid = struct {
    // Authenticator is currently busy handling a request with the given
    // Cid. `null` means not busy.
    busy: ?Cid = null,
    // Time in ms the initialization packet was received.
    begin: ?std.Io.Timestamp = null,
    // Command to be executed.
    cmd: ?Cmd = null,
    // The ammount of expected data bytes (max is: 64 - 7 + 128 * (64 - 5) = 7609).
    bcnt_total: u16 = 0,
    // Data bytes already received.
    bcnt: u16 = 0,
    // Last sequence number (continuation packet).
    seq: ?u8 = 0,
    // Data buffer.
    // All clients (CIDs) share the same buffer, i.e. only one request
    // can be handled at a time. This buffer is also used for some of
    // the response data.
    data: [MAX_DATA_SIZE]u8 = undefined,

    channels: std.ArrayListUnmanaged(Cid),

    /// Io interface for:
    /// - CSPRNG
    io: std.Io,

    allocator: std.mem.Allocator,

    const timeout: u64 = 250; // 250 milli second timeout

    pub fn init(a: std.mem.Allocator, io: std.Io) @This() {
        return .{
            .channels = .empty,
            .io = io,
            .allocator = a,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.channels.deinit(self.allocator);
    }

    /// Check if the given CID represents a broadcast channel.
    fn isBroadcast(cid: Cid) bool {
        return cid == 0xffffffff;
    }

    fn allocateChannelId(self: *@This()) !Cid {
        if (self.channels.items.len >= 20) {
            // Remove first entry inserted
            _ = self.channels.orderedRemove(0);
        }

        const rng_impl = std.Random.IoSource{ .io = self.io };
        const rng = rng_impl.interface();

        const cid = rng.int(u32);

        self.channels.append(self.allocator, cid) catch |e| {
            std.log.err("unable to allocate memory for CID {d}", .{cid});
            return e;
        };
        return cid;
    }

    fn isValidChannel(self: *@This(), cid: Cid) bool {
        for (self.channels.items) |_cid| {
            if (_cid == cid) return true;
        }
        return false;
    }

    pub fn handle(self: *@This(), packet: []const u8) ?CtapHidMsg {
        //std.log.err("{s}", .{std.fmt.fmtSliceHexLower(packet)});
        if (self.begin != null and self.begin.?.untilNow(self.io, .real).toMilliseconds() > CtapHid.timeout) {
            // the previous transaction has timed out -> reset
            self.reset();
        }

        if (self.busy == null) { // initialization packet
            if (packet.len < 7) { // packet is too short
                return self.@"error"(ErrorCodes.other);
            } else if (packet[4] & 0x80 == 0) {
                // expected initialization packet but found continuation packet
                return self.@"error"(ErrorCodes.invalid_cmd);
            }

            self.busy = misc.sliceToInt(Cid, packet[0..4]);
            self.begin = std.Io.Timestamp.now(self.io, .real);

            if (!isBroadcast(self.busy.?) and !self.isValidChannel(self.busy.?)) {
                return self.@"error"(ErrorCodes.invalid_channel);
            }

            self.cmd = @as(Cmd, @enumFromInt(packet[4] & 0x7f));
            self.bcnt_total = misc.sliceToInt(u16, packet[5..7]);

            const l = packet.len - 7;
            @memcpy(self.data[0..l], packet[7..]);
            self.bcnt = @as(u16, @intCast(l));
        } else { // continuation packet
            if (packet.len < 5) {
                return self.@"error"(ErrorCodes.other);
            }

            if (misc.sliceToInt(Cid, packet[0..4]) != self.busy.?) {
                // tell client that the authenticator is busy!
                return self.@"error"(ErrorCodes.channel_busy);
            } else if (packet[4] & 0x80 != 0) {
                // expected continuation packet but found initialization packet
                return self.@"error"(ErrorCodes.invalid_cmd);
            } else if ((self.seq == null and packet[4] > 0) or (self.seq != null and packet[4] != self.seq.? + 1)) {
                // unexpected sequence number
                return self.@"error"(ErrorCodes.invalid_seq);
            }

            self.seq = packet[4];
            const l = packet.len - 5;
            @memcpy(self.data[self.bcnt .. self.bcnt + l], packet[5..]);
            self.bcnt += @as(u16, @intCast(l));
        }

        if (self.bcnt >= self.bcnt_total and self.busy != null and self.cmd != null) {
            defer self.reset();

            // verify that the channel is valid
            switch (self.cmd.?) {
                .init => {
                    // init can be called using the broadcast channel or an allocated one
                    if (!isBroadcast(self.busy.?) and !self.isValidChannel(self.busy.?)) {
                        return self.@"error"(ErrorCodes.invalid_channel);
                    }
                },
                else => {
                    // all other commands require a valid channel
                    if (!self.isValidChannel(self.busy.?)) {
                        return self.@"error"(ErrorCodes.invalid_channel);
                    }
                },
            }

            // execute the command
            switch (self.cmd.?) {
                .msg => {
                    return CtapHidMsg.new(self.cmd.?, self.busy.?, self.data[0..self.bcnt]);
                },
                .cbor => {
                    return CtapHidMsg.new(self.cmd.?, self.busy.?, self.data[0..self.bcnt]);
                },
                .init => {
                    if (isBroadcast(self.busy.?)) {
                        const channel = self.allocateChannelId() catch {
                            self.deinit();
                            return null;
                        };

                        // If sent on the broadcast CID, it requests the device to allocate a
                        // unique 32-bit channel identifier (CID) that can be used by the
                        // requesting application during its lifetime.
                        const ir = InitResponse.new(
                            misc.sliceToInt(Nonce, self.data[0..8]),
                            channel,
                            false,
                            true,
                            false,
                        );
                        ir.serialize(self.data[0..InitResponse.SIZE]);
                        return CtapHidMsg.new(self.cmd.?, self.busy.?, self.data[0..InitResponse.SIZE]);
                    } else {
                        // The device then responds with the CID of the channel it received
                        // the INIT on, using that channel.
                        misc.intToSlice(self.data[0..], self.busy.?);
                        return CtapHidMsg.new(self.cmd.?, self.busy.?, self.data[0..4]);
                    }
                },
                .ping => {
                    return CtapHidMsg.new(self.cmd.?, self.busy.?, self.data[0..self.bcnt]);
                },
                .cancel => {
                    return null;
                },
                else => {
                    std.debug.print("invalid {X}\n", .{self.data[0..self.bcnt]});
                    return self.@"error"(ErrorCodes.invalid_cmd);
                },
            }
        }

        return null;
    }

    fn reset(s: *@This()) void {
        s.busy = null;
        s.begin = null;
        s.cmd = null;
        s.bcnt_total = 0;
        s.bcnt = 0;
        s.seq = null;
    }

    fn @"error"(self: *@This(), e: ErrorCodes) CtapHidMsg {
        const es = switch (e) {
            .invalid_cmd => "\x01",
            .invalid_par => "\x02",
            .invalid_len => "\x03",
            .invalid_seq => "\x04",
            .msg_timeout => "\x05",
            .channel_busy => "\x06",
            .lock_required => "\x0a",
            .invalid_channel => "\x0b",
            else => "\x7f",
        };

        const response = CtapHidMsg.new(
            Cmd.err,
            if (self.busy) |c| c else 0xffffffff,
            es,
        );

        self.reset();
        return response;
    }
};
