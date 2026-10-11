# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub: open the [Security tab](https://github.com/remymazmanian/wp-passkey-first/security) and choose **Report a vulnerability**. Don't open a public issue for a vulnerability.

Include the plugin, WordPress and PHP versions, what you found and, if you can, steps or a request that reproduce it. You'll get a reply within a few days, and fixes are released as soon as they're ready.

## Supported versions

Security fixes go into the latest release.

## Scope

Especially welcome:

- the built-in WebAuthn verifier (`includes/class-pf-webauthn.php`): signature, origin, relying-party, challenge and counter checks, and CBOR parsing
- passwordless sign-in (`includes/class-pf-passwordless.php`): who can enrol or sign in, session handling, and how it interacts with the Two Factor plugin
- ways around the enrolment policy or the "Required" password block

Two-factor passkeys themselves are verified by the Two Factor plugin and its WebAuthn provider; report problems in those to their maintainers.
