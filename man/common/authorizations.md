# Authorization Formatting

Authorization for use of an object in TPM2.0 can come in 3 different forms:
1. Password
2. HMAC
3. Sessions

**NOTE:** "Authorizations default to the **EMPTY PASSWORD** when not specified".

## Passwords

Passwords are interpreted in two forms, string and hex-string. A string password is not
interpreted, and is directly used for authorization. A hex-string password is converted from
a hexidecimal form into a byte array form, thus allowing passwords with non-printable
and/or terminal un-friendly characters.

By default passwords are assumed to be in the string form. Password form is specified
with special prefix values, they are:

  * **str**: Used to indicate it is a raw string. Useful for escaping a password that starts
         with the "hex:" prefix.
  * **hmac**: Use to indicate, the subsequent string specified be used in calculating
          the command buffer HMAC to prevent presenting clear text passwords on
          the TPM interfaces. See CVE-2017-7524 for details.
  * **hex**: Used when specifying a password in hex string format.
  * **session**: A file containing session metadata about a previously started session.
  * **pcr**: A PCR specification for authenticating against a PCR policy.

## HMAC

Generate an HMAC ticket for authorization. Useful for preventing a clear text password being sent to the tpm.

### Example
```
tpm2_nvwrite -x 0x1500018 -a 0x1500018 -P "hmac:hmacpass" test.nv
```

## PCR Policy

To authenticate with a PCR policy, prefix the option argument with the *pcr* keyword, followed by colon, and a *pcr spec*.
A pcr spec consists of a `<bank specifier>=<pcr file>`, where `<bank-spec>` is mandatory and `=<pcr-file>` is optional.

### PCR Bank Specifiers `<bank-spec>`

PCR Bank Specifier follow the below specification:

```
<BANK>:<PCR>[,<PCR>]
```

multiple banks may be separated by '+'.

For example:

```
sha:3,4+sha256:5,6
```
will select PCRs 3 and 4 from the SHA bank and PCRs 5 and 6
from the SHA256 bank.

**Note**: PCR Selections allow for up to 5 hash to pcr selection mappings.
This is a limitaion in design in the single call to the tpm to
get the pcr values.


### PCR File `<pcr-file>`

This is a computed file that matches the specifier that contains the
PCR values. This prevents a PCR read. This file can be generated
via **tpm2_pcrlist** as in the below example:
```
tpm2_pcrlist -Q -L sha1:0,1,2,3 -o pcr.dat
```

### Example
```
echo -n "policy locked" | tpm2_nvwrite -x 0x1500016 -a 0x1500016 -P"pcr:sha1:0,1,2,3=pcr.dat"

```

## Sessions

When using a policy session to authorize the use of an object, one prefixes the option argument
with the *session* keyword followed by a colon. You then indicate a path to a session file that was created
with tpm2_startauthsession(1).

### Example
```
# Start a session
tpm2_startauthsession -a -S s.dat

# Do some policy event, in this case we will satisfy a PCR policy
tpm2_policypcr -S s.dat -L sha1:0,1,2,3 -F pcr.dat -f policy.dat

# Use that session for authorization
tpm2_unseal -P"session:s.dat" -c key.ctx
```
