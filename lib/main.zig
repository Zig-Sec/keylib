const std = @import("std");

pub const VERSION: []const u8 = "0.3.5";

/// Used by multiple data types
pub const common = struct {
    /// Representation of a relying party
    pub const RelyingParty = @import("common/RelyingParty.zig");
    /// Representation of a user
    pub const User = @import("common/User.zig");
    /// This enumeration defines the valid credential types
    pub const PublicKeyCredentialType = @import("common/PublicKeyCredentialType.zig").PublicKeyCredentialType;
    pub const PublicKeyCredentialParameters = @import("common/PublicKeyCredentialParameters.zig");
    /// Identifies a specific public key credential
    pub const PublicKeyCredentialDescriptor = @import("common/PublicKeyCredentialDescriptor.zig");
    /// Definitions for various transports for communicating with clients
    pub const AuthenticatorTransports = @import("common/AuthenticatorTransports.zig").AuthenticatorTransports;
    /// Parameters to influence authenticator operation
    pub const AuthenticatorOptions = @import("common/AuthenticatorOptions.zig");
    /// WebAuthn Attestation Statement Format Identifiers
    pub const AttestationStatementFormatIdentifiers = @import("common/AttestationStatementFormatIdentifiers.zig").AttestationStatementFormatIdentifiers;
    /// Attested credential data is a byte-array added to the authenticator data when
    /// generating an attestation object
    pub const AttestedCredentialData = @import("common/AttestedCredentialData.zig");
    /// The authenticator data structure encodes contextual bindings made by the authenticator
    pub const AuthenticatorData = @import("common/AuthenticatorData.zig");
    pub const AttestationStatement = @import("common/AttestationStatement.zig").AttestationStatement;
    /// Authenticator (CTAP) versions
    pub const AuthenticatorVersions = @import("common/AuthenticatorVersions.zig").AuthenticatorVersions;
    /// An authenticator’s supported certifications (FIPS, FIDO, ...)
    pub const Certifications = @import("common/Certifications.zig");
    /// Type of attestation issued (None, Slef, ...)
    pub const AttestationType = @import("common/AttestationType.zig").AttestationType;
    pub const dt = @import("common/data_types.zig");

    test "common tests" {
        _ = RelyingParty;
        _ = User;
        _ = PublicKeyCredentialType;
        _ = PublicKeyCredentialParameters;
        _ = PublicKeyCredentialDescriptor;
        _ = AuthenticatorTransports;
        _ = AuthenticatorOptions;
        _ = AttestationStatementFormatIdentifiers;
        _ = AttestedCredentialData;
        _ = AuthenticatorData;
        _ = AttestationStatement;
        _ = AuthenticatorVersions;
        _ = Certifications;
        _ = AttestationType;
    }
};

/// Client to authenticator protocol
pub const ctap = struct {
    /// Request data structures
    pub const request = struct {
        /// authenticatorMakeCredential request data structure
        pub const MakeCredential = @import("ctap/request/MakeCredential.zig");
        /// authenticatorGetAssertion request data structure
        pub const GetAssertion = @import("ctap/request/GetAssertion.zig");
        /// authenticatorClientPin request data structure
        pub const ClientPin = @import("ctap/request/ClientPin.zig");
        /// authenticatorCredentialManagement request data structure
        pub const CredentialManagement = @import("ctap/request/CredentialManagement.zig");
    };

    /// Response data structures
    pub const response = struct {
        /// authenticatorMakeCredential response data structure (attestation object)
        pub const MakeCredential = @import("ctap/response/MakeCredential.zig");
        /// authenticatorGetAssertion response data structure
        pub const GetAssertion = @import("ctap/response/GetAssertion.zig");
        /// authenticatorClientPin response data structure
        pub const ClientPin = @import("ctap/response/ClientPin.zig");
        /// authenticatorCredentialManagement response data structure
        pub const CredentialManagement = @import("ctap/response/CredentialManagement.zig");
    };

    /// Algorithms and data types for crypto
    pub const crypto = struct {
        /// Diffie-Hellman key exchange
        pub const dh = struct {
            pub const ecdh = @import("ctap/crypto/ecdh.zig");
            /// Elliptic curve diffie-hellman using the P-256 curve
            ///
            /// This is used to exchange a shared secret between client and
            /// authenticator when using the pinUvAuth protocol versions 1 and 2.
            pub const EcdhP256 = ecdh.EcdhP256;
        };

        /// Abstract interface for signature algorithms
        pub const SigAlg = @import("ctap/crypto/SigAlg.zig");

        /// Default signature algorithms ready to use
        ///
        /// Use SigAlg to implement your own!
        pub const algorithms = struct {
            /// Elliptic curve digital signature algorithm using curve P256 and hashing algorithm SHA256
            pub const Es256 = @import("ctap/crypto/sigalgs/Es256.zig").Es256;
        };

        /// This is the hash (computed using SHA-256) of the JSON-compatible
        /// serialization of client data, as constructed by the client
        pub const ClientDataHash = [32]u8;

        /// The master secret is a value randomly generated unique value that
        /// is used to derive subkeys.
        pub const master_secret = @import("ctap/crypto/master_secret.zig");

        pub const Id = @import("ctap/crypto/Id.zig");
    };

    /// PIN/UV Auth Protocol
    ///
    /// A specific PIN/UV auth protocol defines an implementation of two interfaces
    /// to cryptographic services: one for the authenticator, and one for the platform.
    pub const pinuv = struct {
        /// Used by multiple data types
        pub const common = struct {
            /// Result of calling authenticate(pinUvAuthToken, clientDataHash)
            pub const PinUvAuthParam = @import("common/data_types.zig").ABS32B;

            /// PIN protocol versions
            pub const PinProtocol = enum(u16) {
                /// Pin protocol version 1
                V1 = 1,
                /// Pin Protocol version 2 for FIPS certified authenticators
                V2 = 2,
            };

            pub const SubCommand = enum(u8) {
                getPinRetries = 0x01,
                getKeyAgreement = 0x02,
                setPIN = 0x03,
                changePIN = 0x04,
                getPinToken = 0x05,
                getPinUvAuthTokenUsingUvWithPermissions = 0x06,
                getUVRetries = 0x07,
                getPinUvAuthTokenUsingPinWithPermissions = 0x09,
            };
        };

        pub fn hash(pin: []const u8) [32]u8 {
            var ph: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(pin, &ph, .{});
            return ph;
        }

        pub const PinUvAuth = @import("ctap/pinuv/PinUvAuth.zig");

        test "pinuv tests" {
            _ = PinUvAuth;
        }
    };

    /// Authenticator related data structures
    pub const authenticator = struct {
        /// Authenticator settings that represent its capabilities
        pub const Settings = @import("ctap/auth/Settings.zig");
        /// Authenticator options
        pub const Options = @import("ctap/auth/Options.zig");
        /// Authenticator response
        pub const Response = @import("ctap/auth/Response.zig").Response;
        /// CTAP2 authenticator
        pub const Auth = @import("ctap/auth/Authenticator.zig").Auth;
        /// Authenticator callbacks the user must provide
        pub const callbacks = @import("ctap/auth/Callbacks.zig");
        /// Representation of a discoverable credential
        pub const Credential = @import("ctap/auth/Credential.zig");
        /// Authenticator related data
        pub const Meta = @import("ctap/auth/Meta.zig");
    };

    /// CTAP commands
    pub const commands = struct {
        /// CTAP command identifier
        pub const Commands = @import("ctap/commands/Commands.zig").Commands;
        /// Authenticator commands
        pub const authenticator = struct {
            pub const authenticatorGetInfo = @import("ctap/commands/authenticator/get_info.zig").authenticatorGetInfo;
            pub const authenticatorMakeCredential = @import("ctap/commands/authenticator/authenticatorMakeCredential.zig").authenticatorMakeCredential;
            pub const authenticatorGetAssertion = @import("ctap/commands/authenticator/authenticatorGetAssertion.zig").authenticatorGetAssertion;
            pub const authenticatorGetNextAssertion = @import("ctap/commands/authenticator/authenticatorGetNextAssertion.zig").authenticatorGetNextAssertion;
            pub const authenticatorClientPin = @import("ctap/commands/authenticator/authenticatorClientPin.zig").authenticatorClientPin;
            pub const authenticatorSelection = @import("ctap/commands/authenticator/authenticatorSelection.zig").authenticatorSelection;
            pub const authenticatorCredentialManagement = @import("ctap/commands/authenticator/authenticatorCredentialManagement.zig").authenticatorCredentialManagement;
            pub const GaErr = @import("ctap/commands/authenticator/authenticatorGetAssertion.zig").GaErr;
        };
    };

    /// CTAP status codes
    pub const StatusCodes = @import("ctap/StatusCodes.zig").StatusCodes;

    /// Transport specific bindings
    pub const transports = struct {
        /// CTAPHID USB bindings
        pub const ctaphid = struct {
            /// CTAPHID commands
            pub const Cmd = @import("ctap/transports/ctaphid/Cmd.zig").Cmd;
            /// CTAPHID message handling
            pub const message = @import("ctap/transports/ctaphid/message.zig");
            /// CTAPHID message handler
            pub const authenticator = @import("ctap/transports/ctaphid/authenticator.zig");
        };
    };

    /// CTAP extensions
    pub const extensions = struct {
        /// Map of optional extensions
        pub const Extensions = @import("ctap/extensions/Extensions.zig");
        /// Protection level for credentials
        pub const CredentialCreationPolicy = @import("ctap/extensions/CredentialCreationPolicy.zig").CredentialCreationPolicy;
        /// Obtaining a shared secret between client and authenticator
        pub const HmacSecret = @import("ctap/extensions/HmacSecret.zig").HmacSecret;
        pub const HmacSecretGet = @import("ctap/extensions/HmacSecret.zig").HmacSecretGet;
    };

    test "ctap tests" {
        _ = request.MakeCredential; // client -> authenticator
        _ = request.GetAssertion;
        _ = request.ClientPin;
        _ = response.MakeCredential; // authenticator -> client
        _ = response.GetAssertion;
        _ = response.ClientPin;
        _ = crypto.dh.ecdh;
        _ = pinuv;
        _ = authenticator.Settings;
        _ = authenticator.Options;
        _ = authenticator.callbacks;
        _ = authenticator.Auth;
        _ = authenticator.Credential;
        _ = authenticator.Meta;
        _ = transports.ctaphid.Cmd;
        _ = transports.ctaphid.message;
        _ = transports.ctaphid.authenticator;
        _ = extensions.CredentialCreationPolicy;
        _ = extensions.Extensions;
        _ = @import("ctap/extensions/HmacSecret.zig");
    }
};

/// Code base that mimics the following browser interfaces for
/// passkeys:
/// - `navigator.credentials.create`
/// - `navigator.credentials.get`
///
/// We only provide part of the data structures required
/// to implement passkey based authentication for native
/// clients using. You don't necessaryly have to use them.
pub const web = @import("web.zig");

test "library tests" {
    _ = common;
    _ = ctap;
    _ = web;
}
