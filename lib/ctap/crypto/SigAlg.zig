const std = @import("std");
const cbor = @import("zbor");
const Allocator = std.mem.Allocator;
const fido = @import("../../main.zig");
const dt = fido.common.dt;

pub const Errors = error{
    BufferToSmall,
    InvalidKeyLength,
    IdentityElement,
    NonCanonical,
};

/// The algorithm used
alg: cbor.cose.Algorithm,
/// Create a new random key-pair
generate: *const fn (allocator: std.mem.Allocator, io: std.Io) cbor.cose.Key,
/// Deterministically creates a new key-pair using the given seed
generateDeterministic: *const fn (seed: []const u8) Errors!cbor.cose.Key,
/// Sign the given data
sign: *const fn (
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    out: []u8,
) Errors![]const u8,
from_priv: *const fn (priv: []const u8) Errors!cbor.cose.Key,
