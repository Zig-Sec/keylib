const std = @import("std");
const hid = @import("hid.zig");

const uhid = @cImport(
    @cInclude("linux/uhid.h"),
);

pub fn create(fd: std.Io.File, io: std.Io, device_name: []const u8) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_CREATE2;
    @memcpy(event.u.create2.name[0..device_name.len], device_name);
    @memcpy(
        event.u.create2.rd_data[0..hid.ReportDescriptorFidoU2f[0..].len],
        hid.ReportDescriptorFidoU2f[0..],
    );
    event.u.create2.rd_size = hid.ReportDescriptorFidoU2f[0..].len;
    event.u.create2.bus = uhid.BUS_USB;
    event.u.create2.vendor = 0x15d9;
    event.u.create2.product = 0x0a37;
    event.u.create2.version = 0;
    event.u.create2.country = 0;

    try uhid_write(fd, io, &event);
}

pub fn uhid_write(fd: std.Io.File, io: std.Io, event: *uhid.uhid_event) !void {
    fd.writeStreamingAll(io, std.mem.asBytes(event)) catch |e| {
        std.log.err("Error writing to uhid: {}\n", .{e});
        return e;
    };
}

pub fn destroy(fd: std.Io.File, io: std.Io) !void {
    var event = std.mem.zeroes(uhid.uhid_event);
    event.type = uhid.UHID_DESTROY;
    return uhid_write(fd, io, &event);
}
