const std = @import("std");
const cbor = @import("zbor");
const keylib = @import("keylib");

pub const Transports = @import("client/Transports.zig");
pub const cbor_commands = @import("client/cbor_commands.zig");
pub const err = @import("client/error.zig");

pub const cose = cbor.cose;
pub const User = keylib.common.User;
pub const RelyingParty = keylib.common.RelyingParty;
pub const MakeCredentialRequestParams = keylib.ctap.request.MakeCredential;
pub const PublicKeyCredentialParameters = keylib.common.PublicKeyCredentialParameters;
pub const ABSPublicKeyCredentialParameters = keylib.common.dt.ABSPublicKeyCredentialParameters;

/// The CTAP2 authenticatorGetInfo (0x04) command
pub const getInfo = cbor_commands.authenticatorGetInfo;
pub const Info = cbor_commands.Info;

/// Obtain a pinUvAuthToken
///
/// On success, returns the tuple: `(PinProtocol, token)`
pub const pinUvAuthToken = cbor_commands.pinUvAuthToken;

/// Reset the given authenticator.
///
/// This command must be send within the first few seconds
/// after a powercycle.
pub const reset = cbor_commands.authenticatorReset;

pub const getKeyAgreement = cbor_commands.client_pin.getKeyAgreement;
pub const changePin = cbor_commands.client_pin.changePin;
pub const setPin = cbor_commands.client_pin.setPin;

/// Create a new credential using the authenticatorMakeCredential command.
///
/// If Rp and User are equal to an existing credential, the existing credential
/// will be overwritten.
pub const makeCredential = cbor_commands.credentials.create;
pub const MakeCredentialResponse = cbor_commands.credentials.MakeCredentialResponse;

/// Obtain a assertion from the authenticator.
pub const getAssertion = cbor_commands.credentials.getAssertion;
pub const getNextAssertion = cbor_commands.credentials.getNextAssertion;
pub const GetAssertionResponse = cbor_commands.credentials.GetAssertionResponse;

/// Credential Management Commands
pub const cm = struct {
    /// Get credential metadata information.
    ///
    // The authenticator MUST support `authenticatorCredentialManagement´.
    pub const getCredsMetadata = cbor_commands.cred_management.getCredsMetadata;
    pub const enumerateRPsBegin = cbor_commands.cred_management.enumerateRPsBegin;
    pub const enumerateRPsGetNextRP = cbor_commands.cred_management.enumerateRPsGetNextRP;
    pub const enumerateCredentialsBegin = cbor_commands.cred_management.enumerateCredentialsBegin;
    pub const enumerateCredentialsGetNextCredential = cbor_commands.cred_management.enumerateCredentialsGetNextCredential;
    pub const deleteCredential = cbor_commands.cred_management.deleteCredential;
};
