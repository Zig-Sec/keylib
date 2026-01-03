const cbor = @import("zbor");
const fido = @import("../main.zig");

const AuthenticatorTransports = fido.common.AuthenticatorTransports;
const PublicKeyCredentialDescriptor = fido.common.PublicKeyCredentialDescriptor;
const AttestationStatementFormatIdentifiers = fido.common.AttestationStatementFormatIdentifiers;
const PublicKeyCredentialParameters = fido.common.PublicKeyCredentialParameters;

pub const ABS32B = cbor.ArrayBackedSlice(32, u8, .Byte);
pub const ABS48B = cbor.ArrayBackedSlice(48, u8, .Byte);
pub const ABS64B = cbor.ArrayBackedSlice(64, u8, .Byte);
pub const ABS80B = cbor.ArrayBackedSlice(80, u8, .Byte);
pub const ABS256B = cbor.ArrayBackedSlice(256, u8, .Byte);
pub const ABS512B = cbor.ArrayBackedSlice(512, u8, .Byte);

pub const ABS32T = cbor.ArrayBackedSlice(32, u8, .Text);
pub const ABS64T = cbor.ArrayBackedSlice(64, u8, .Text);
pub const ABS128T = cbor.ArrayBackedSlice(128, u8, .Text);

// Currently there are 6 different transports defined (usb, nfc, ble, smart-card, hybrid, and internal)
pub const ABSAuthenticatorTransports = cbor.ArrayBackedSlice(6, AuthenticatorTransports, .Other);
// TODO: 6 could be not enough if there are many credentials registered for a site
pub const ABSPublicKeyCredentialDescriptor = cbor.ArrayBackedSlice(6, PublicKeyCredentialDescriptor, .Other);
pub const ABSAttestationStatementFormatIdentifiers = cbor.ArrayBackedSlice(6, AttestationStatementFormatIdentifiers, .Other);
pub const ABSPublicKeyCredentialParameters = cbor.ArrayBackedSlice(6, PublicKeyCredentialParameters, .Other);
pub const ABSAuthenticatorData = cbor.ArrayBackedSlice(256, u8, .Byte);
