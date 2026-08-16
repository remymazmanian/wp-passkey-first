# Passkey First

Passkey-first two-factor policy for WordPress administrators.

WordPress already has good passkey support through two plugins: [Two Factor](https://wordpress.org/plugins/two-factor/) provides the 2FA framework, and [WebAuthn Provider for Two Factor](https://wordpress.org/plugins/two-factor-provider-webauthn/) adds passkeys as a method. Installed on their own they are two more entries in the plugin list and no policy. What neither provides is **policy**: nothing makes the passkey the default prompt, nothing requires an administrator to enrol one, and the weaker fallbacks stay enabled forever.

This plugin is that policy layer. It contains no cryptography and stores no credentials — the two plugins above keep doing that work. It decides *who must use what*.

## What it does

- **Passkey first.** When a covered user has a passkey enrolled, the login prompt asks for it first instead of whichever method happened to be primary.
- **Require enrolment.** Optionally, users in covered roles must enrol a passkey. Until they do, wp-admin shows a persistent notice; after a configurable grace period, admin screens redirect to the profile page until enrolment is done. The profile page itself is never blocked, so nobody gets locked out of the fix.
- **Retire weak fallbacks.** Optionally removes the email-code provider for covered users. Email 2FA is only as strong as the mailbox behind it.
- **Role-scoped.** Applies to the roles you pick (administrators by default). Everyone else is untouched.

## What it deliberately does not do

- No cryptography, no credential storage — that stays in the provider plugin.
- No changes for uncovered roles.
- No REST or application-password interference: enforcement targets interactive wp-admin sessions only, so API clients using Application Passwords keep working.
- Enforcement ships **off** by default. Enrol your own passkey, then switch it on.


## Passwordless sign-in (experimental — use at your own risk)

Version 0.2.0 adds built-in WebAuthn passwordless login: enrol passkeys on
your profile, and covered users can sign in with a fingerprint, face, or
device PIN — no password, and no username either, since discoverable
credentials identify the account.

**Its status, stated plainly:** the verifier follows the WebAuthn
specification, fails closed on anything unexpected, and ships with a fixture
test suite (`tests/`) covering registration, assertion and seven negative
paths. It has **not yet had independent security review**. Until it has,
treat the feature as use-at-your-own-risk:

- Prefer **Optional** mode, which adds the passkey button while keeping
  password sign-in available.
- **Required** mode disables form passwords only for covered users who hold a
  passkey. Application Passwords, REST, XML-RPC and WP-CLI are unaffected, and
  `define( 'PF_ALLOW_PASSWORDS', true );` in `wp-config.php` re-enables
  passwords instantly.
- Enrol at least two passkeys before requiring them.

Independent review is the gate before this feature loses the experimental
label. If you review it, findings are very welcome.

## Guide

A full setup walkthrough lives at [remymazmanian.com/passkey-login-wordpress-guide](https://remymazmanian.com/passkey-login-wordpress-guide/).

## Requirements

| | |
|---|---|
| WordPress | 6.5+ |
| PHP | 7.4+ |
| Plugins | Two Factor, WebAuthn Provider for Two Factor |
| HTTPS | required for WebAuthn in production |

You install **one plugin**. Passkey First declares the other two through
WordPress's native plugin dependencies (`Requires Plugins`), so core prompts
for them at install time and will not activate Passkey First without them.
They stay separate on disk deliberately: they contain the WebAuthn
cryptography and receive their own security updates, which bundling would cut
you off from. If they ever go missing the settings page says so and nothing is
enforced.

## Settings

**Settings → Passkey First**

| Setting | Default | Notes |
|---|---|---|
| Covered roles | administrator | checkboxes for every editable role |
| Passkey is the primary prompt | on | only applies where a passkey exists |
| Require a passkey | **off** | the enforcement switch |
| Grace period | 7 days | 0 enforces immediately |
| Retire email codes | off | removes the email provider for covered users |

Settings live in a single option, `passkey_first_settings`, so they can be read and written with WP-CLI:

```bash
wp option get passkey_first_settings
wp option patch update passkey_first_settings require_passkey 1
```

## How enforcement behaves

1. A covered user without a passkey signs in. A timestamp is recorded and an admin notice appears with a link to the enrolment section of their profile and the time remaining.
2. During the grace period, nothing is blocked.
3. After the grace period, wp-admin requests redirect to `profile.php#two-factor-options` until a passkey is enrolled. Profile, AJAX, cron and REST requests are exempt, so enrolment itself — and machine clients — keep working.
4. The moment a passkey is enrolled, the policy is satisfied and the redirect stops.

## Licence

Copyright (C) 2026 Remy Mazmanian.

GPL-2.0-or-later. The full text is in [`LICENSE`](LICENSE); the copyright notice ships in [`NOTICE`](NOTICE).
