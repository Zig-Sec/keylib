/// Supported version of the authenticator.
pub const AuthenticatorVersions = enum {
    FIDO_2_3,
    FIDO_2_2,
    FIDO_2_1,
    FIDO_2_1_PRE,
    /// For CTAP2/FIDO2/Web Authentication authenticators.
    FIDO_2_0,
    /// For CTAP1/U2F authenticators.
    U2F_V2,

    pub fn to_string(self: @This()) []const u8 {
        return switch (self) {
            .FIDO_2_3 => "FIDO_2_3",
            .FIDO_2_2 => "FIDO_2_2",
            .FIDO_2_1 => "FIDO_2_1",
            .FIDO_2_1_PRE => "FIDO_2_1_PRE",
            .FIDO_2_0 => "FIDO_2_0",
            .U2F_V2 => "U2F_V2",
        };
    }
};
