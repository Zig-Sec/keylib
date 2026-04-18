from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
)

# Simple Options
simple_registration_options = generate_registration_options(
    rp_id="zigtoberfest.de",
    rp_name="Zigtoberfest",
    user_name="david",
)

print("\n[Registration Options - Simple]")
print(options_to_json(simple_registration_options))

# Complex Options
complex_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_id=bytes([1, 2, 3, 4]),
    user_name="lee",
    user_display_name="Lee",
    attestation=AttestationConveyancePreference.DIRECT,
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
    ),
    challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
    exclude_credentials=[
        PublicKeyCredentialDescriptor(id=b"1234567890"),
    ],
    supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
    timeout=12000,
    hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
)

print("\n[Registration Options - Complex]")
print(options_to_json(complex_registration_options))
