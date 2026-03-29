//! The authenticatorMakeCredential response structure contains an attestation object
//! plus additional information
//!
//! ```
//! // ATTESTATION OBJECT
/// ________________________________________________________
/// | "fmt": "fido-u2f" | "attStmt": ... | "authData": ... |
/// --------------------------------------------------------
///                             |               |
///  ----------------------------               V
///  |
///  |     32 bytes      1        4            var             var
///  |  ____________________________________________________________
///  |  | RP ID hash | FLAGS | COUNTER | ATTESTED CRED. DATA | EXT |
///  |  ------------------------------------------------------------
///  |                    |                      |
///  |                    V                      |
///  |          _____________________            |
///  |          |ED|AT|0|0|0|UV|0|UP|            |
///  |          ---------------------            |
///  |                                           V
///  |          _______________________________________________
///  |          | AAGUID | L | CREDENTIAL ID | CRED. PUB. KEY |
///  |          -----------------------------------------------
///  |           16 bytes  2        L          var len (COSE key)
///  |
///  V                      __________________________________
/// if Basic or Privacy CA: |"alg": ...|"sig": ...|"x5c": ...|
///                         ----------------------------------
///                         _______________________________________
/// if ECDAA:               |"alg": ...|"sig": ...|"ecdaaKeyId": ..|
/// ```
const std = @import("std");
const cbor = @import("zbor");
const fido = @import("../../main.zig");

const AttestationStatementFormatIdentifiers = fido.common.AttestationStatementFormatIdentifiers;
const AuthenticatorData = fido.common.AuthenticatorData;
const AttestationStatement = fido.common.AttestationStatement;

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The attestation statement format identifier
fmt: AttestationStatementFormatIdentifiers,
/// Authenticator data
authData: AuthenticatorData,
/// Attestation statement
attStmt: AttestationStatement,
/// Indicates whether an enterprise attestation was returned for this credential.
/// If epAtt is absent or present and set to false, then an enterprise attestation
/// was not returned. If epAtt is present and set to true, then an enterprise
/// attestation was returned
epAtt: ?bool = null,
/// Contains the largeBlobKey for the credential, if requested with the largeBlobKey
/// extension
largeBlobKey: ?[]const u8 = null,

pub fn deinit(self: *const @This(), allocator: std.mem.Allocator) void {
    self.attStmt.deinit(allocator);
}

pub fn cborStringify(self: *const @This(), _: cbor.Options, out: *std.Io.Writer) !void {
    const AO = struct {
        fmt: AttestationStatementFormatIdentifiers,
        authData: []const u8,
        attStmt: AttestationStatement,
    };

    // Encode authData which is not CBOR
    const ad = try self.authData.encode();

    try cbor.stringify(
        AO{ .fmt = self.fmt, .authData = ad.get(), .attStmt = self.attStmt },
        .{
            .field_settings = &.{
                .{ .name = "fmt", .field_options = .{ .alias = "1", .serialization_type = .Integer } },
                .{ .name = "authData", .field_options = .{ .alias = "2", .serialization_type = .Integer } },
                .{ .name = "attStmt", .field_options = .{ .alias = "3", .serialization_type = .Integer } },
                .{ .name = "eppAtt", .field_options = .{ .alias = "4", .serialization_type = .Integer } },
                .{ .name = "largeBlobKey", .field_options = .{ .alias = "5", .serialization_type = .Integer } },
            },
            .ignore_override = true,
        },
        out,
    );
}

pub fn cborParse(item: cbor.DataItem, options: cbor.Options) !@This() {
    if (item.getType() != .Map) return error.UnsupportedType;

    var map = item.map().?;

    // fmt
    var kv = map.next();
    if (kv == null) return error.MissingField;

    var key = kv.?.key.int();
    if (key == null or key.? != 1) return error.UnexpectedItemValue;
    const fmt = try cbor.parse(
        fido.common.AttestationStatementFormatIdentifiers,
        kv.?.value,
        options,
    );

    // authData
    kv = map.next();
    if (kv == null) return error.MissingField;

    key = kv.?.key.int();
    if (key == null or key.? != 2) return error.UnexpectedItemValue;
    const value = kv.?.value.string();
    if (value == null) return error.UnexpectedItemValue;
    var reader = std.Io.Reader.fixed(value.?);
    const authData = AuthenticatorData.decode(&reader) catch return error.Malformed;

    // attStmt
    kv = map.next();
    if (kv == null) return error.MissingField;

    key = kv.?.key.int();
    if (key == null or key.? != 3) return error.UnexpectedItemValue;
    const attStmt = try cbor.parse(
        fido.common.AttestationStatement,
        kv.?.value,
        options,
    );

    return .{
        .fmt = fmt,
        .authData = authData,
        .attStmt = attStmt,
        // TODO: eppAtt -> 4
        // TODO: largeBlobKey -> 5
    };
}

test "attestationObject encoding - no attestation" {
    const allocator = std.testing.allocator;
    //var authData = std.ArrayList(u8).init(allocator);
    //defer authData.deinit();
    var attObj = std.Io.Writer.Allocating.init(allocator);
    defer attObj.deinit();

    const k = cbor.cose.Key.fromP256Pub(.Es256, try EcdsaP256Sha256.PublicKey.fromSec1("\x04\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52"));
    var serialized_cred = std.Io.Writer.Allocating.init(allocator);
    defer serialized_cred.deinit();
    try cbor.stringify(&k, .{ .enum_serialization_type = .Integer }, &serialized_cred.writer);

    const acd = try fido.common.AttestedCredentialData.new(
        .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        &.{ 0xb3, 0xf8, 0xcd, 0xb1, 0x80, 0x20, 0x91, 0x76, 0xfa, 0x20, 0x1a, 0x51, 0x6d, 0x1b, 0x42, 0xf8, 0x02, 0xa8, 0x0d, 0xaf, 0x48, 0xd0, 0x37, 0x88, 0x21, 0xa6, 0xfb, 0xdd, 0x52, 0xde, 0x16, 0xb7, 0xef, 0xf6, 0x22, 0x25, 0x72, 0x43, 0x8d, 0xe5, 0x85, 0x7e, 0x70, 0xf9, 0xef, 0x05, 0x80, 0xe9, 0x37, 0xe3, 0x00, 0xae, 0xd0, 0xdf, 0xf1, 0x3f, 0xb6, 0xa3, 0x3e, 0xc3, 0x8b, 0x81, 0xca, 0xd0 },
        serialized_cred.written(),
    );

    const ad = AuthenticatorData{
        .rpIdHash = .{ 0x21, 0x09, 0x18, 0x5f, 0x69, 0x3a, 0x01, 0xea, 0x1a, 0x26, 0x41, 0xf8, 0x2d, 0x52, 0xfb, 0xae, 0xee, 0x0a, 0x4f, 0x47, 0xe3, 0x37, 0x4d, 0xfe, 0xf8, 0x70, 0x83, 0x8d, 0xe4, 0x9b, 0x0e, 0x97 },
        .flags = .{
            .up = 1,
            .rfu1 = 0,
            .uv = 0,
            .be = 0,
            .bs = 0,
            .rfu2 = 0,
            .at = 1,
            .ed = 0,
        },
        .signCount = 0,
        .attestedCredentialData = acd,
    };

    //try ad.encode(authData.writer());

    const ao = @This(){
        .fmt = .@"packed",
        .authData = ad,
        .attStmt = AttestationStatement{ .none = .{} },
    };

    try cbor.stringify(ao, .{ .allocator = allocator }, &attObj.writer);

    // {1: "packed", 2: h'2109185f693a01ea1a2641f82d52fbaeee0a4f47e3374dfef870838de49b0e974100000000000000000000000000000000000000000040b3f8cdb180209176fa201a516d1b42f802a80daf48d0378821a6fbdd52de16b7eff6222572438de5857e70f9ef0580e937e300aed0dff13fb6a33ec38b81cad0a5010203262001215820d9f4c2a352136f19c9a95da8824ab5cdc4d5631ebcfd5bdbb0bfff253609129e225820ef404b880765576007888a3ed6abffb4257b7123553325d450613cb5bc9a3a52', 3: {}}
    try std.testing.expectEqualSlices(u8, "\xa3\x01\x66\x70\x61\x63\x6b\x65\x64\x02\x58\xc4\x21\x09\x18\x5f\x69\x3a\x01\xea\x1a\x26\x41\xf8\x2d\x52\xfb\xae\xee\x0a\x4f\x47\xe3\x37\x4d\xfe\xf8\x70\x83\x8d\xe4\x9b\x0e\x97\x41\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\xb3\xf8\xcd\xb1\x80\x20\x91\x76\xfa\x20\x1a\x51\x6d\x1b\x42\xf8\x02\xa8\x0d\xaf\x48\xd0\x37\x88\x21\xa6\xfb\xdd\x52\xde\x16\xb7\xef\xf6\x22\x25\x72\x43\x8d\xe5\x85\x7e\x70\xf9\xef\x05\x80\xe9\x37\xe3\x00\xae\xd0\xdf\xf1\x3f\xb6\xa3\x3e\xc3\x8b\x81\xca\xd0\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20\xd9\xf4\xc2\xa3\x52\x13\x6f\x19\xc9\xa9\x5d\xa8\x82\x4a\xb5\xcd\xc4\xd5\x63\x1e\xbc\xfd\x5b\xdb\xb0\xbf\xff\x25\x36\x09\x12\x9e\x22\x58\x20\xef\x40\x4b\x88\x07\x65\x57\x60\x07\x88\x8a\x3e\xd6\xab\xff\xb4\x25\x7b\x71\x23\x55\x33\x25\xd4\x50\x61\x3c\xb5\xbc\x9a\x3a\x52\x03\xa0", attObj.written());
}
