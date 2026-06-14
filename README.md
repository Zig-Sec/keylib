# keylib

<a href="https://liberapay.com/r4gus/donate"><img alt="Donate using Liberapay" src="https://liberapay.com/assets/widgets/donate.svg"></a>

FIDO2 compatible *authenticator* and *client* library written in [Zig](https://ziglang.org/).

This package can serve two purposes:

1. Create FIDO2/ Passkey compatible authenticators:
    - Examples 
        - [PassKeeZ](https://codeberg.org/r4gus/PassKeeZ) - A FIDO/ Passkey compatible Authenticator for Linux
        - [PassKeeZero](https://codeberg.org/r4gus/PassKeeZ-Zero) - Turn your Raspberry Pi Zero 2 W into a FIDO2 security key
    - Test the example using one of the following test sites:
        - [passkey.org](https://passkey.org)
        - [webauthn.io](https://webauthn.io/)
        - [passkeys.io](https://www.passkeys.io/)
    - but you can also use the library on embedded devices, e.g. to create your own security key (similar to YubiKey, SoloKey, ...)
2. Add FIDO2/ Passkey support to your application using the client module.
    - We provide a variety of examples [here](example/client/README.md)
    - On linux it might be required to install the `udev` developer package, e.g. `libudev-dev` on Ubuntu.

> The CTAP2 specification offers a lot of configurations for authenticators. If you're looking for a specific example and can't find it here or run into a bug, consider opening an issue. I'm open to add new features as long as you're also willing to contribute (in some form) to the project.

| Zig version | keylib version |
|:-----------:|:--------------:|
| 0.13.0      | 0.5.0, 0.5.1, 0.5.2, 0.5.3 |
| 0.14.x      | 0.6.0, 0.6.1 |
| 0.15.x      | 0.7.0, 0.8.0 |
| 0.16.x      | master |

## Getting Started

First add this project as a dependency to your `build.zig.zon` file:

```bash
# Replace <VERSION TAG> with the version you want to use ...
zig fetch --save https://codeberg.org/r4gus/keylib/archive/<VERSION TAG>.tar.gz
# e.g. zig fetch --save https://codeberg.org/r4gus/keylib/archive/0.8.0.tar.gz

# ... or use the master branch
zig fetch --save git+https://codeberg.org/r4gus/keylib
```

Then, within your `build.zig` add the following code:

```zig
const keylib_dep = b.dependency("keylib", .{
    .target = target,
    .optimize = optimize,
});
const keylib_module = keylib_dep.module("keylib");

// For the uhid module (support for virtual authenticators on Linux) use:
// const uhid_module = keylib_dep.module("uhid");

// For the cliet module use:
// const client_module = keylib_dep.module("clientlib");

// ...

exe.root_module.addImport("keylib", keylib_module);
// or add one or more of the other modules as needed...
```

Then within your project just use `@import("keylib")` (or one of the other modules).

## Authenticator Framework Design

![keylib design](static/design.png)

## QA

<details>
<summary><ins>What is FIDO2?</ins></summary>

FIDO2 is a protocol designed for authentication purposes. It can be used as single factor (e.g., as a replacement for password based authentication) or as a second factor (e.g., instead of OTPs).

</details>

<details>
<summary><ins>I've heard the term Passkey but what is that?</ins></summary>

Passkey is a marketing term which is used to refer to a specific FIDO2 authenticator configuration. A authenticator can be configured to use so called discoverable credentials (also referred to as resident keys). Those credentials are stored somewhere on your device, e.g. in a encrypted database. Devices can also be protected by some form of user verification. This can be a PIN or a built in user verification method like a finger print scanner. Passkey refers to FIDO2 using discoverable credentials and some form of user verification. 

Please note that this is only one interpretation of what PassKey means as the term itself is nowhere defined (see also [Passkeys's: A Shattered Dream](https://fy.blackhats.net.au/blog/2024-04-26-passkeys-a-shattered-dream/)).

</details>

<details>
<summary><ins>How does it work?</ins></summary>

FIDO2 uses asymmetric cryptography to ensure the authenticity of the user. A unique credential (key-pair) is created for each relying party (typically a web server) and bound to the relying party id (e.g., google.com). The private key stays on the authenticator and the public key is stored by the relying party. When a user wants to authenticate herself, the relying party sends a nonce (a random byte string meant to be only used once) and some other data, over the client (typically your web browser), to the authenticator. The authenticator looks up the required private key and signs the data with it. The generated signature can then be verified by the relying party using the corresponding public key.

</details>

<details>
<summary><ins>What is the difference between FIDO2, PassKey and WebAuthn?</ins></summary>

You might have noticed that FIDO2, PassKey and even WebAuthn are often used interchangeably by some articles and people which can be confusing, especially for people new to the protocol. Here is a short overview:

* `FIDO2` Protocol consisting of two sub-protocols: Client to Authenticator Protocol 2 (`CTAP2`) and Web Authentication (`WebAuthn`)
* `CTAP2` Specification that governs how a authenticator (e.g. YubiKey) should behave and how a authenticator and a client (e.g. web-browser) can communicate with each other.
* `WebAuthn` Specification that defines how web applications can use a authenticator for authentication. This includes the declaration of data structures and Java Script APIs.
* `PassKey`: A authenticator with a specific configuration (see above).

</details>


<details>
<summary><ins>Why should I use FIDO2?</ins></summary>

FIDO2 has a lot of advantages compared to passwords:

1. No secret information is shared, i.e. the private key stays on the authenticator or is protected, e.g. using key wrapping.
2. Each credential is bound to a relying party id (e.g. google.com), which makes social engineering attacks, like phishing websites, quite difficult (as long as the client verifies the relying party id properly).
3. Users don't have to be concerned with problems like password complexity.
4. If well implemented, FIDO2 provides a better user experience (e.g., faster logins).
5. A recent paper showed that with some adoptions, FIDO2 is ready for a post quantum world under certain conditions ([FIDO2, CTAP 2.1, and WebAuthn 2: Provable Security and Post-Quantum Instantiation, Cryptology ePrint Archive, Paper 2022/1029](https://eprint.iacr.org/2022/1029.pdf)).

</details>

<details>
<summary><ins>Are there problems with FIDO2?</ins></summary>

Yes, there are:

1. The two FIDO2 subprotocols (CTAP2 and WebAuthn) are way more difficult to implement, compared to password authentication. 
2. There are more points of failure because you have three parties that are involved in the authentication process (authenticator, client, relying party).
3. Currently not all browsers support the CTAP2 protocol well (especially on Linux).
4. There is no way to verify that a client is trustworthy:
    * Rogue clients may communicate with a authenticator without your consent
    * Clients may display wrong information
5. The 4th layer introduced for Android, IOS, and Windows to connect authenticators and clients internally could be used as a man in the middle.

</details>

<details>
<summary><ins>Does this library work with all browsers?</ins></summary>

Answering this question isn't straightforward. The library, by its nature, is designed to be independent of any particular platform, meaning that you have the responsibility of supplying it with data for processing. To put it differently, you're in charge of creating a functional interface for communicating with a client, typically a web browser. On Linux, we offer a wrapper for the uhid interface, simplifying the process of presenting an application as a USB HID device with a Usage Page of F1D0 on the bus.

**There are known issues with older browsers (including Firefox)**. Newer browser versions should work fine. Tested with:

| Browser | Supported? | Tested version| Notes |
|:-------:|:----------:|:-------------:|:-----:|
| Cromium   | &#9989;    | 119.0.6045.159 (Official Build) Arch Linux (64-bit) | |
| Brave | &#9989; | Version 1.62.153 Chromium: 121.0.6167.85 (Official Build) (64-bit) | |
| Firefox | &#9989; | 122.0 (64-bit) |  |
| Opera | &#9989; | version: 105.0.4970.16 chromium: 119.0.6045.159 | |

**Please let me know if you run into issues!**

</details>

<details>
<summary><ins>Does this library implement the whole CTAP2 sepc?</ins></summary>

No, we do not fully implement the entire [CTAP2](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#intro) specification. In the initial version of this library, which can be found on GitHub, our aim was to remain completely platform-agnostic and cover most of the CTAP2 specification. However, this approach introduced complexities for both users and developers. The current version of this library strikes a balance between usability and feature completeness.

We offer support for operations like __authenticatorMakeCredential__, __authenticatorGetAssertion__, __authenticatorGetInfo__, and __authenticatorClientPin__, with built-in support for __user verification__ and the __pinUvAuth protocol__ (versions 1 and 2). You are responsible for handling data management tasks (such as secure storage, updates, and deletions), verifying user presence, and conducting user verification. These responsibilities are fulfilled by implementing the necessary callbacks used to instantiate an authenticator (refer to the "Getting Started" section for details).

</details>

## Resources

- [CTAP2.0](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html) - FIDO Alliance
- [CTAP2.1](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#intro) - FIDO Alliance
- [CTAP2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html#intro) - FIDO Alliance
- [WebAuthn](https://www.w3.org/TR/webauthn-3/) - W3C
- [CBOR RFC8949](https://www.rfc-editor.org/rfc/rfc8949.html) - C. Bormann and P. Hoffman
- [Credential Exchange Protocol (CXP)](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20240522.html) - FIDO Alliance
- [Credential Exchange Format (CXF)](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html) - FIDO Alliance
- Proprietary Credential Exchange APIs
    - [Android (Credential Providerevents)](https://developer.android.com/jetpack/androidx/releases/credentials-providerevents#1.0.0-alpha06)
    - [Apple (ASCredentialExportManager)](https://developer.apple.com/documentation/authenticationservices/ascredentialexportmanager)
    - `"It’s important to note that CXF only defines the format. Because the Credential Exchange Protocol (CXP) is still under development, today’s transfers are limited to local, on-device migrations. Cross-device and cross-platform exchanges will be possible once CXP is finalized and adopted by platforms."` - [1Password](https://www.1password.community/blog/developer-blog/portability-without-compromise-1password-helps-author-a-new-standard-for-secure-/163208)
- Credential Provider API (examples)
    - [Android (docs)](https://developer.android.com/identity/sign-in/credential-provider)
        - [Credential Provider Example](https://github.com/android/identity-samples/tree/main/CredentialProvider/MyVault) - Official example by Android
    - [iOS](https://github.com/Dashlane/apple-credential-provider-example) - MIT licensed example by Dashlane
    - [Windows](https://github.com/microsoft/Windows-classic-samples/tree/main/Samples/PasskeyManager) - Official example released by Microsoft

---

__FIDO2/Passkey test sites__:
- [passkey.org](https://passkey.org/)
- [webauthn.io](https://webauthn.io/)

## Random Ideas

<details>
<summary><ins>Protecting secrets using a PIN</ins></summary>

Microcontrollers like the rp2040 allow the creation of cheap authenticators but they provide no means to somehow protect
secrets like master passwords, PINs, or credentials. One way one could securely store sensitive data is by making PIN
protection mandatory. Note that this is a tradeof and will render some counters (like the pin retry counter) useless if
an attacker has physical access to the chip, as one can not protect the counters from manipulation.

1. Your authenticator has PIN protection enabled by default, i.e. on first boot a default password is set. You should also
set the _force pin change_ flag to "encourge" the user to change his password.
2. Also on first boot, you create a master password which will encrypt all sensitive data using a AEAD cipher. The master
password itself is encrypted using a secret derived from the PIN.
3. Metadata like retry counters are not encrypted (make sure you __DONT__ store the PIN unencrypted!). This still allows
the blocking of a authenticator (in fact you should automatically reset the authenticator if the retry counter hits zero)
but an attack with physical access could potentially reset the counters giving him unlimited retries.
4. Make sure you disallow any operations on sensitive data without prior authentication (__alwaysUv__).
5. Make sure you only use PIN authentication.
6. During authentication you intercept the PIN hash (after decryption) and derive a deterministic secret from it
using a key derivation function of you choice (e.g. HKDF; but it must always be the same). This secret must have
the same lifetime as the pinUvAuthToken! 
7. When the application requires a credential (or other sensitive data) you decrypt the master secret using the
derived secret and the decrypt the actual data with the master secret. If the application wants to overwrite data,
you decrypt the data, update it and the encrypt it using the master secret.
8. After you're done, make sure to overwrite any plain text information no longer required.
9. On pin change, just decrypt the master secret and then re-encrypt it using the secret derived
from the new PIN hash.

</details>
