const std = @import("std");
const fido = @import("../../../main.zig");
const cbor = @import("zbor");
const SigAlg = fido.ctap.crypto.SigAlg;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const dt = fido.common.dt;

pub const Es256 = SigAlg{
    .alg = .Es256,
    .generate = generate,
    .generateDeterministic = generateDeterministic,
    .sign = sign,
    .from_priv = from_priv,
};

pub fn generate(allocator: std.mem.Allocator, io: std.Io) cbor.cose.Key {
    // Create key pair
    return cbor.cose.Key.es256(allocator, io);
}

pub fn generateDeterministic(seed: []const u8) SigAlg.Errors!cbor.cose.Key {
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed[0..32].*);
    return cbor.cose.Key.fromP256PrivPub(.Es256, kp.secret_key, kp.public_key);
}

pub fn sign(
    raw_private_key: []const u8,
    data_seq: []const []const u8,
    out: []u8,
) SigAlg.Errors![]const u8 {
    if (raw_private_key.len != 32) return error.InvalidKeyLength;

    var kp = try EcdsaP256Sha256.KeyPair.fromSecretKey(
        try EcdsaP256Sha256.SecretKey.fromBytes(raw_private_key[0..32].*),
    );
    var signer = try kp.signer(null);

    // Append data that should be signed together
    for (data_seq) |data| {
        signer.update(data);
    }

    // Sign the data
    const sig = try signer.finalize();
    var buffer: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&buffer);

    if (out.len < der.len) return error.BufferToSmall;
    @memcpy(out[0..der.len], der);
    return out[0..der.len];
}

pub fn from_priv(priv: []const u8) SigAlg.Errors!cbor.cose.Key {
    if (priv.len != 32) return error.InvalidKeyLength;

    var kp = try EcdsaP256Sha256.KeyPair.fromSecretKey(
        try EcdsaP256Sha256.SecretKey.fromBytes(priv[0..32].*),
    );

    const sec1 = kp.public_key.toUncompressedSec1();
    const pubk = cbor.cose.Key{ .P256 = .{
        .alg = .Es256,
        .x = sec1[1..33].*,
        .y = sec1[33..65].*,
    } };

    return pubk;
}
