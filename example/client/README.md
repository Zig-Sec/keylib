# Examples

The following examples are provided for clients:

- `manifest`

```
Prints a list of available FIDO devices.
```

- `info <device>`

```
Print information about the specified <device>.
```

- `setpin <device> <newPin> <curPin>`

```
Set <newPin> as the new PIN for <device>. If <curPin> is provided,
the device's PIN is changed from <curPin> to <newPin>.
```

- `reset <device>`

```
Performs a factory reset on <device>.
```

- `cred [-t es256] [-rv] [-p pin] [--origin rpId] [--uid userid] <device>`

```
Creates a new credential on <device>.

Example 1: Create a new credential with the given user id and the rpId "zigtoberfest.de" using the PIN "1234" for authentication on device 0 (see `manifest` command).

$ ./cred -r --uid 00112233445566778899aabbccddeeff --origin "zigtoberfest.de" -p 1234 0
```

- `metadata <device> [pin] [y/n]`

```
Obtain credentials metadata information from the <device>.

Use the `y` option for YubiKeys (and possibly other authenticators using the 
credMgmtPreview) as some use a differnt command code.

Example: $ ./metadata 0 1234 y
```

- `enumrp <device> [pin] [y/n]`

```
Enumerate all relying parties present on <device>.

Multiple resident keys (passkeys) can share the same relying party.

Use the `y` option for YubiKeys (and possibly other authenticators using the 
credMgmtPreview) as some use a differnt command code.

Example: $ ./enumrp 0 1234 y
```

- `./enumcred [-y] [-p <pin>] <device> <origin/rpId>`

```
Enumerate the resident keys for <origin> present on <device>.

Use the `y` option for YubiKeys (and possibly other authenticators using the 
credMgmtPreview) as some use a differnt command code.

Example: $ ./enumcred -y -p 1234 0 zigtoberfest.de
```

- `./delete [-y] [-p <pin>] <device> <credId>`

```
Remove the credential corresponding to <credId> from <device>.

<credId> MUST be provided in hex (see `enumcred`).

Use the `y` option for YubiKeys (and possibly other authenticators using the 
credMgmtPreview) as some use a differnt command code.

Example: $ ./delete -y -p 1234 0 c903a5912b4708a0b5aad34aa31dce5a2067978885be6d4824d5352543443dc2ff377e4168987003c21a312beffdaa78
```
