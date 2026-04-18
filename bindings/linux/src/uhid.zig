const std = @import("std");
const hid = @import("hid.zig");
const common = @import("common.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

const PATH = "/dev/uhid";

const create = common.create;
const uhid_write = common.uhid_write;
const destroy = common.destroy;

pub const Uhid = struct {
    device: std.Io.File,
    io: std.Io,

    pub fn open(io: std.Io, device_name: []const u8) !@This() {
        var device = std.Io.Dir.openFileAbsolute(io, PATH, .{
            .mode = .read_write,
        }) catch |e| {
            std.log.err("Can't open uhid-cdev {s}\n", .{PATH});
            return e;
        };
        errdefer device.close(io);

        const flags = std.c.fcntl(device.handle, 3, @as(c_int, @intCast(0)));
        if (flags < 0) {
            std.log.err("Can't get file stats", .{});
            return error.GetFlags;
        }
        const ret = std.c.fcntl(device.handle, 4, flags | 2048);
        if (ret < 0) {
            std.log.err("Can't set file to non-blocking", .{});
            return error.SetFlags;
        }

        create(device, io, device_name) catch |e| {
            std.log.err("Unabel to create CTAPHID device", .{});
            return e;
        };

        return .{
            .device = device,
            .io = io,
        };
    }

    pub fn close(self: *const @This()) void {
        destroy(self.device, self.io) catch {
            std.log.err("Unabel to destroy UHID device", .{});
        };
        self.device.close(self.io);
    }

    pub fn read(self: *const @This(), out: *[64]u8) ?[]u8 {
        var event = std.mem.zeroes(uhid.uhid_event);
        _ = self.device.readStreaming(self.io, &.{std.mem.asBytes(&event)}) catch {
            return null;
        };

        if (event.type != uhid.UHID_OUTPUT) {
            return null;
        }

        if (event.u.output.size < 1) return null;

        @memcpy(out[0 .. event.u.output.size - 1], event.u.output.data[1..event.u.output.size]);
        return out[0 .. event.u.output.size - 1];
    }

    pub fn write(self: *const @This(), in: []const u8) !void {
        if (in.len > 64) return error.InvalidSizedPacket;

        var rev = std.mem.zeroes(uhid.uhid_event);
        rev.type = uhid.UHID_INPUT;
        @memcpy(rev.u.input.data[0..in.len], in[0..]);
        rev.u.input.size = @as(c_ushort, @intCast(in.len));

        uhid_write(self.device, self.io, @ptrCast(&rev)) catch |e| {
            std.log.err("failed to send CTAPHID packet\n", .{});
            return e;
        };
    }
};
