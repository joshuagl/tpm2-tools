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

  * str: - Used to indicate it is a raw string. Useful for escaping a password that starts
         with the "hex:" prefix.
  * hmac:- Use to indicate, the subsequent string specified be used in calculating
           the command buffer HMAC to prevent presenting clear text passwords on
           the TPM interfaces. See CVE-2017-7524 for details.
  * hex: - Used when specifying a password in hex string format.

## HMAC

HMAC tickets can be presented as hex escaped passwords.

## Sessions

When using a policy session to authorize the use of an object, prefix the option argument
with the *session* keyword.  Then indicate a path to a session file that was created
with tpm2_startauthsession(1).
