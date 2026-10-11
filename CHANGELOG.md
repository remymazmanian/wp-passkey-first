# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/remymazmanian/wp-passkey-first/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/remymazmanian/wp-passkey-first/releases/tag/v0.2.0
