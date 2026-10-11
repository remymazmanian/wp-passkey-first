# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-10-11

### Fixed

- On the login screen, the "Log In" button overlapped the bottom of the "Sign in with a passkey" button. WordPress's login stylesheet floats primary buttons to the right, which collapsed the passkey button's container. It's now laid out as its own row, with the usual gap above Remember Me and Log In.

## [0.3.0] - 2026-10-10

Makes passwordless sign-in work for users who have Two Factor turned on, and makes it follow its own settings: Off now means off, and only covered roles can use it. Also hardens the passkey verifier. Passwordless sign-in is still experimental and has not had an independent security audit.

### Fixed

- Passkey sign-in works for users with the Two Factor plugin turned on. Two Factor cleared the new login cookie and showed its own prompt, so the passkey button failed for exactly the users the plugin is for. A passkey sign-in now counts as two-factor and the session is marked that way.
- Setting passwordless sign-in to Off refuses every passkey sign-in, including passkeys already enrolled. Before, existing passkeys kept working.
- Only users in the covered roles can enrol a passkey or sign in with one, as the settings and README describe.
- Passkey sign-ins go through the same account checks as a password sign-in, so accounts that another plugin locks or disables, and spam-flagged accounts on multisite, can't use a passkey to get in.
- A passkey whose signature counter drops back to zero is rejected as a possible clone, as the WebAuthn specification requires. Before, this also reset the stored counter.
- The "Remember Me" box and the page you were heading to are honoured after a passkey sign-in.
- The settings screen shows the right version number.
- The two-factor prompt is only pointed at the Two Factor plugin's own passkey method.
- Uninstalling the plugin now deletes stored passwordless passkeys along with its settings.

### Added

- Administrators who can edit a user can see and remove that user's passkeys on their profile, for example when a device is lost or someone leaves.
- Automated tests: a software passkey that produces real ES256 and RS256 signatures, 35 verifier tests, and 26 end-to-end tests against WordPress with Two Factor installed, run by GitHub Actions on PHP 7.4 to 8.5.
- A security policy in `SECURITY.md`.

### Changed

- Passkeys enrolled for passwordless sign-in count toward "Require a passkey" only while passwordless sign-in is switched on.
- The settings screen and README now say which passkeys this plugin stores: none for the two-factor policy, and passwordless passkeys on each user's account.

### Security

- A sign-in can only be completed by the browser that started it, which blocks login cross-site request forgery.
- Each sign-in challenge can be used once, even by two requests at the same moment.
- Anonymous sign-in challenge requests are rate-limited per IP address.
- Passkeys used inside another site's frame (cross-origin) are rejected.
- The passkey data parser rejects truncated, deeply nested, duplicated or padded input cleanly.
- RSA passkeys must be 2048 bits or larger.


## [0.2.0] - 2026-08-17

First tagged release of Passkey First, a WordPress plugin that makes the passkey the main two-factor method for the roles you choose, working with the Two Factor and WebAuthn Provider for Two Factor plugins. Compared with the initial 0.1.0 code, it adds experimental passwordless sign-in, a guided settings screen and native plugin dependencies.

### Added

- Passwordless sign-in with passkeys, experimental and off by default. In Optional mode the login form gains a "Sign in with a passkey" button, and no username is needed. This feature has not had an independent security review yet, so Optional is the recommended setting.
- Passkeys section on your own profile page to add passkeys, see when each was added and last used, and remove them.
- Required mode for passwordless sign-in, which turns off password sign-in on the login form for covered users who hold a passkey. Application Passwords, REST, XML-RPC and WP-CLI keep working, and `define( 'PF_ALLOW_PASSWORDS', true );` in `wp-config.php` turns passwords back on.
- Setup checklist on the settings screen that ticks off each step as the site reaches it: dependencies active, your own passkey enrolled, every covered user enrolled, enforcement on.
- "How it works" help tab on the settings screen.

### Changed

- Redesigned settings screen, with the policy form next to a status panel (dependencies, passwordless mode, enforcement, enrolment count) and a table of covered users showing who has a passkey.
- Native plugin dependencies: WordPress now prompts for Two Factor and WebAuthn Provider for Two Factor when you install Passkey First, and will not activate it without them.
- Minimum WordPress version raised from 6.0 to 6.5, which plugin dependencies require.
- Passkeys added for passwordless sign-in now count as enrolled for the "Require a passkey" policy.

https://github.com/remymazmanian/wp-passkey-first/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/remymazmanian/wp-passkey-first/releases/tag/v0.3.1
[0.3.0]: https://github.com/remymazmanian/wp-passkey-first/releases/tag/v0.3.0
[0.2.0]: https://github.com/remymazmanian/wp-passkey-first/releases/tag/v0.2.0
