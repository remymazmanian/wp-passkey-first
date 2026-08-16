<?php
/**
 * Plugin Name: Passkey First
 * Plugin URI: https://remymazmanian.com/
 * Description: Passkey-first two-factor policy for administrators. Coordinates the Two Factor plugin and its WebAuthn provider: makes the passkey the primary prompt, can require enrolment for chosen roles with a grace period, and can retire weaker fallbacks.
 * Version: 0.2.0
 * Requires at least: 6.5
 * Requires PHP: 7.4
 * Requires Plugins: two-factor, two-factor-provider-webauthn
 * Author: Remy Mazmanian
 * Author URI: https://remymazmanian.com/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: passkey-first
 */

/**
 * Copyright (C) 2026 Remy Mazmanian
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */


defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/class-pf-webauthn.php';
require_once __DIR__ . '/includes/class-pf-passwordless.php';

final class Passkey_First {

	const OPTION = 'passkey_first_settings';

	/** Provider keys used by the Two Factor plugin and the WebAuthn provider. */
	const P_WEBAUTHN = 'TwoFactor_Provider_WebAuthn';
	const P_TOTP     = 'Two_Factor_Totp';
	const P_EMAIL    = 'Two_Factor_Email';
	const P_BACKUP   = 'Two_Factor_Backup_Codes';

	private static $instance;

	public static function instance() {
		return self::$instance ?: self::$instance = new self();
	}

	private function __construct() {
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
		add_action( 'admin_init', array( $this, 'enforce' ), 20 );
		add_action( 'admin_notices', array( $this, 'notices' ) );
		add_filter( 'two_factor_primary_provider_for_user', array( $this, 'primary_provider' ), 10, 2 );
		add_filter( 'two_factor_enabled_providers_for_user', array( $this, 'trim_providers' ), 10, 2 );
	}

	/* ---------------------------------------------------------- settings */

	public static function defaults() {
		return array(
			'roles'           => array( 'administrator' ),
			'passkey_primary' => 1,
			'require_passkey' => 0,
			'grace_days'      => 7,
			'disable_email'   => 0,
			'pw_mode'         => 'off',
		);
	}

	public static function settings() {
		$s = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $s ) ? $s : array(), self::defaults() );
	}

	public function register_settings() {
		register_setting( 'passkey_first', self::OPTION, array(
			'type'              => 'array',
			'sanitize_callback' => function ( $in ) {
				$d   = self::defaults();
				$out = array();
				$roles = isset( $in['roles'] ) && is_array( $in['roles'] ) ? $in['roles'] : $d['roles'];
				$out['roles'] = array_values( array_intersect( $roles, array_keys( get_editable_roles() ) ) );
				if ( ! $out['roles'] ) {
					$out['roles'] = $d['roles'];
				}
				$out['passkey_primary'] = empty( $in['passkey_primary'] ) ? 0 : 1;
				$out['require_passkey'] = empty( $in['require_passkey'] ) ? 0 : 1;
				$out['disable_email']   = empty( $in['disable_email'] ) ? 0 : 1;
				$out['grace_days']      = max( 0, min( 90, (int) ( $in['grace_days'] ?? $d['grace_days'] ) ) );
				$mode           = $in['pw_mode'] ?? 'off';
				$out['pw_mode'] = in_array( $mode, array( 'off', 'optional', 'required' ), true ) ? $mode : 'off';
				return $out;
			},
		) );
	}

	public function add_settings_page() {
		$hook = add_options_page( 'Passkey First', 'Passkey First', 'manage_options', 'passkey-first', array( $this, 'render_settings_page' ) );
		add_action( 'load-' . $hook, array( $this, 'help_tab' ) );
	}

	public function help_tab() {
		get_current_screen()->add_help_tab( array(
			'id'      => 'pf-help',
			'title'   => __( 'How it works', 'passkey-first' ),
			'content' =>
				'<p>' . esc_html__( 'Passkey First is policy only. Credentials are created and verified by the Two Factor plugin and its WebAuthn provider; this plugin decides who must use them.', 'passkey-first' ) . '</p>' .
				'<p>' . esc_html__( 'Rollout order matters: enrol your own passkey first, confirm every covered user shows "passkey" in the covered-users table, and only then switch on "Require a passkey". Enforcement never blocks the profile page, so an unenrolled user can always reach the fix.', 'passkey-first' ) . '</p>' .
				'<p>' . esc_html__( 'API clients authenticating with Application Passwords are unaffected: enforcement only touches interactive wp-admin sessions.', 'passkey-first' ) . '</p>',
		) );
	}

	public function render_settings_page() {
		$s = self::settings();
		$deps = $this->dependencies_met();
		$covered = get_users( array( 'role__in' => $s['roles'], 'fields' => 'all' ) );
		$enrolled = 0;
		foreach ( $covered as $u ) {
			if ( $this->user_has_passkey( $u->ID ) ) {
				$enrolled++;
			}
		}
		?>
		<style>
			.pf-wrap{max-width:960px;}
			.pf-head{display:flex;align-items:baseline;gap:.6rem;margin:0 0 4px;}
			.pf-head h1{padding:0;margin:0;}
			.pf-ver{font-family:Menlo,Consolas,monospace;font-size:11px;color:#646970;border:1px solid #c3c4c7;border-radius:3px;padding:1px 6px;background:#fff;}
			.pf-sub{color:#646970;margin:0 0 20px;max-width:66ch;}
			.pf-grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(260px,1fr);gap:20px;align-items:start;}
			@media(max-width:960px){.pf-grid{grid-template-columns:1fr;}}
			.pf-card{background:#fff;border:1px solid #c3c4c7;border-radius:4px;box-shadow:0 1px 1px rgba(0,0,0,.04);}
			.pf-card h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:#1d2327;margin:0;padding:12px 16px;border-bottom:1px solid #f0f0f1;}
			.pf-card .inside{padding:16px;}
			.pf-field{padding:14px 0;border-bottom:1px solid #f0f0f1;}
			.pf-field:first-child{padding-top:2px;}
			.pf-field:last-child{border-bottom:0;padding-bottom:2px;}
			.pf-field>strong{display:block;margin-bottom:6px;}
			.pf-field .description{margin:6px 0 0;}
			.pf-roles label{display:inline-block;margin:0 14px 4px 0;}
			.pf-status{list-style:none;margin:0;padding:0;}
			.pf-status li{display:flex;justify-content:space-between;gap:10px;padding:7px 0;border-bottom:1px solid #f0f0f1;font-size:13px;}
			.pf-status li:last-child{border-bottom:0;}
			.pf-ok{color:#00701a;font-weight:600;}
			.pf-warn{color:#996800;font-weight:600;}
			.pf-bad{color:#b32d2e;font-weight:600;}
			.pf-users{width:100%;border-collapse:collapse;font-size:13px;}
			.pf-users td{padding:7px 0;border-bottom:1px solid #f0f0f1;}
			.pf-users tr:last-child td{border-bottom:0;}
			.pf-users td:last-child{text-align:right;}
			.pf-danger{border-left:3px solid #b32d2e;padding-left:13px;}
			.pf-steps{margin:0;padding:0 0 0 2px;list-style:none;counter-reset:pf;}
			.pf-steps li{counter-increment:pf;padding:6px 0 6px 30px;position:relative;font-size:13px;border-bottom:1px solid #f0f0f1;}
			.pf-steps li:last-child{border-bottom:0;}
			.pf-steps li::before{content:counter(pf);position:absolute;left:0;top:6px;width:20px;height:20px;border-radius:50%;text-align:center;line-height:20px;font-size:11px;font-weight:600;background:#f0f0f1;color:#646970;}
			.pf-step-done{color:#646970;text-decoration:line-through;text-decoration-color:#c3c4c7;}
			.pf-step-done::before{content:"\2713" !important;background:#00701a !important;color:#fff !important;}
		</style>
		<div class="wrap pf-wrap">
			<div class="pf-head">
				<h1><?php esc_html_e( 'Passkey First', 'passkey-first' ); ?></h1>
				<span class="pf-ver">0.1.0</span>
			</div>
			<p class="pf-sub"><?php esc_html_e( 'Policy layer over Two Factor and its WebAuthn provider: the passkey becomes the primary prompt, enrolment can be required per role, and weak fallbacks can be retired. This plugin stores no credentials.', 'passkey-first' ); ?></p>

			<div class="pf-grid">
				<form method="post" action="options.php" class="pf-card">
					<h2><?php esc_html_e( 'Policy', 'passkey-first' ); ?></h2>
					<div class="inside">
						<?php settings_fields( 'passkey_first' ); ?>

						<div class="pf-field pf-roles">
							<strong><?php esc_html_e( 'Covered roles', 'passkey-first' ); ?></strong>
							<?php foreach ( get_editable_roles() as $slug => $role ) : ?>
								<label>
									<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[roles][]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $s['roles'], true ) ); ?>>
									<?php echo esc_html( translate_user_role( $role['name'] ) ); ?>
								</label>
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'The policy applies to users holding any of these roles. Everyone else is untouched.', 'passkey-first' ); ?></p>
						</div>

						<div class="pf-field">
							<label>
								<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[passkey_primary]" value="1" <?php checked( $s['passkey_primary'] ); ?>>
								<strong style="display:inline"><?php esc_html_e( 'Passkey is the primary prompt', 'passkey-first' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'When a covered user has a passkey enrolled, the login asks for it first. Other methods stay reachable as fallbacks.', 'passkey-first' ); ?></p>
						</div>

						<div class="pf-field pf-danger">
							<label>
								<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[require_passkey]" value="1" <?php checked( $s['require_passkey'] ); ?>>
								<strong style="display:inline"><?php esc_html_e( 'Require a passkey', 'passkey-first' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Covered users must enrol. During the grace period wp-admin nags; after it, admin screens redirect to the profile until enrolment is done. The profile page is never blocked. Enrol your own passkey before switching this on.', 'passkey-first' ); ?></p>
							<p style="margin:10px 0 0;">
								<label>
									<?php esc_html_e( 'Grace period', 'passkey-first' ); ?>
									<input type="number" min="0" max="90" name="<?php echo esc_attr( self::OPTION ); ?>[grace_days]" value="<?php echo esc_attr( $s['grace_days'] ); ?>" class="small-text">
									<?php esc_html_e( 'days. 0 enforces immediately.', 'passkey-first' ); ?>
								</label>
							</p>
						</div>

						<div class="pf-field pf-danger">
							<strong><?php esc_html_e( 'Passwordless sign-in', 'passkey-first' ); ?> <span style="font-weight:400;color:#996800;">(<?php esc_html_e( 'experimental', 'passkey-first' ); ?>)</span></strong>
							<select name="<?php echo esc_attr( self::OPTION ); ?>[pw_mode]">
								<option value="off" <?php selected( $s['pw_mode'] ?? 'off', 'off' ); ?>><?php esc_html_e( 'Off', 'passkey-first' ); ?></option>
								<option value="optional" <?php selected( $s['pw_mode'] ?? 'off', 'optional' ); ?>><?php esc_html_e( 'Optional — "Sign in with a passkey" button appears on the login form', 'passkey-first' ); ?></option>
								<option value="required" <?php selected( $s['pw_mode'] ?? 'off', 'required' ); ?>><?php esc_html_e( 'Required — covered users with a passkey can no longer use their password on the login form', 'passkey-first' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Built-in WebAuthn: sign in with a fingerprint, face, or device PIN instead of a password. Enrol passkeys on your profile first. "Required" leaves Application Passwords, REST and WP-CLI untouched, and the PF_ALLOW_PASSWORDS constant in wp-config.php is the break-glass that re-enables passwords.', 'passkey-first' ); ?></p>
							<p class="description" style="color:#996800;"><strong><?php esc_html_e( 'Use at your own risk.', 'passkey-first' ); ?></strong> <?php esc_html_e( 'This implementation passes its test suite, fails closed, and follows the WebAuthn specification — but it has not yet had independent security review. "Optional" keeps password sign-in available and is the recommended setting until it has.', 'passkey-first' ); ?></p>
						</div>

						<div class="pf-field">
							<label>
								<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[disable_email]" value="1" <?php checked( $s['disable_email'] ); ?>>
								<strong style="display:inline"><?php esc_html_e( 'Retire email codes', 'passkey-first' ); ?></strong>
							</label>
							<p class="description"><?php esc_html_e( 'Removes the email-code fallback for covered users. Email 2FA is only as strong as the mailbox behind it.', 'passkey-first' ); ?></p>
						</div>

						<?php submit_button(); ?>
					</div>
				</form>

				<div>
					<div class="pf-card" style="margin-bottom:20px;">
						<h2><?php esc_html_e( 'Setup', 'passkey-first' ); ?></h2>
						<div class="inside">
							<?php
							$me_enrolled = $this->user_has_passkey( get_current_user_id() );
							$all_enrolled = $covered && $enrolled === count( $covered );
							$steps = array(
								array( $deps, __( 'Dependencies active', 'passkey-first' ), '' ),
								array( $me_enrolled, __( 'Enrol your own passkey', 'passkey-first' ), admin_url( 'profile.php#two-factor-options' ) ),
								array( $all_enrolled, __( 'Every covered user enrolled', 'passkey-first' ), '' ),
								array( (bool) $s['require_passkey'], __( 'Switch on "Require a passkey"', 'passkey-first' ), '' ),
							);
							echo '<ol class="pf-steps">';
							foreach ( $steps as $st ) {
								echo '<li class="' . ( $st[0] ? 'pf-step-done' : 'pf-step-open' ) . '">';
								echo $st[2] && ! $st[0] ? '<a href="' . esc_url( $st[2] ) . '">' . esc_html( $st[1] ) . '</a>' : esc_html( $st[1] );
								echo '</li>';
							}
							echo '</ol>';
							?>
							<p class="description"><?php esc_html_e( 'Do these in order. Steps tick themselves off as the site reaches them.', 'passkey-first' ); ?></p>
						</div>
					</div>

					<div class="pf-card" style="margin-bottom:20px;">
						<h2><?php esc_html_e( 'Status', 'passkey-first' ); ?></h2>
						<div class="inside">
							<ul class="pf-status">
								<li><span><?php esc_html_e( 'Two Factor plugin', 'passkey-first' ); ?></span>
									<?php echo class_exists( 'Two_Factor_Core' ) ? '<span class="pf-ok">' . esc_html__( 'active', 'passkey-first' ) . '</span>' : '<span class="pf-bad">' . esc_html__( 'missing', 'passkey-first' ) . '</span>'; ?></li>
								<li><span><?php esc_html_e( 'WebAuthn provider', 'passkey-first' ); ?></span>
									<?php echo $this->webauthn_provider_key() ? '<span class="pf-ok">' . esc_html__( 'active', 'passkey-first' ) . '</span>' : '<span class="pf-bad">' . esc_html__( 'missing', 'passkey-first' ) . '</span>'; ?></li>
								<li><span><?php esc_html_e( 'Passwordless', 'passkey-first' ); ?></span>
									<?php $pm = $s['pw_mode'] ?? 'off'; echo 'off' === $pm ? '<span class="pf-warn">' . esc_html__( 'off', 'passkey-first' ) . '</span>' : '<span class="pf-ok">' . esc_html( $pm ) . '</span>'; ?></li>
								<li><span><?php esc_html_e( 'Enforcement', 'passkey-first' ); ?></span>
									<?php echo $s['require_passkey'] ? '<span class="pf-ok">' . esc_html__( 'on', 'passkey-first' ) . '</span>' : '<span class="pf-warn">' . esc_html__( 'off', 'passkey-first' ) . '</span>'; ?></li>
								<li><span><?php esc_html_e( 'Enrolled', 'passkey-first' ); ?></span>
									<span class="<?php echo $enrolled === count( $covered ) && $covered ? 'pf-ok' : 'pf-warn'; ?>"><?php echo esc_html( $enrolled . ' / ' . count( $covered ) ); ?></span></li>
							</ul>
						</div>
					</div>

					<div class="pf-card">
						<h2><?php esc_html_e( 'Covered users', 'passkey-first' ); ?></h2>
						<div class="inside">
							<?php if ( $covered ) : ?>
							<table class="pf-users">
								<?php foreach ( $covered as $u ) : ?>
								<tr>
									<td><?php echo esc_html( $u->user_login ); ?></td>
									<td><?php echo $this->user_has_passkey( $u->ID ) ? '<span class="pf-ok">' . esc_html__( 'passkey', 'passkey-first' ) . '</span>' : '<span class="pf-warn">' . esc_html__( 'none', 'passkey-first' ) . '</span>'; ?></td>
								</tr>
								<?php endforeach; ?>
							</table>
							<?php else : ?>
							<p class="description"><?php esc_html_e( 'No users hold a covered role.', 'passkey-first' ); ?></p>
							<?php endif; ?>
						</div>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/* ---------------------------------------------------------- helpers */

	public function dependencies_met() {
		return class_exists( 'Two_Factor_Core' ) && $this->webauthn_provider_key();
	}

	/**
	 * The WebAuthn provider key as registered with Two Factor.
	 * Matched loosely so a renamed provider class still resolves.
	 */
	public function webauthn_provider_key() {
		if ( ! class_exists( 'Two_Factor_Core' ) ) {
			return '';
		}
		foreach ( array_keys( Two_Factor_Core::get_providers() ) as $key ) {
			if ( false !== stripos( $key, 'webauthn' ) ) {
				return $key;
			}
		}
		return '';
	}

	public function user_is_covered( $user ) {
		$user = $user instanceof WP_User ? $user : get_userdata( (int) $user );
		if ( ! $user ) {
			return false;
		}
		return (bool) array_intersect( self::settings()['roles'], (array) $user->roles );
	}

	public function user_has_passkey( $user_id ) {
		if ( class_exists( 'PF_Passwordless' ) && PF_Passwordless::has_passkey( $user_id ) ) {
			return true;
		}
		if ( ! class_exists( 'Two_Factor_Core' ) ) {
			return false;
		}
		$key = $this->webauthn_provider_key();
		$enabled = Two_Factor_Core::get_enabled_providers_for_user( get_userdata( $user_id ) );
		return $key && in_array( $key, (array) $enabled, true );
	}

	/* ---------------------------------------------------------- policy */

	/** Ask for the passkey first when one is enrolled. */
	public function primary_provider( $provider, $user_id ) {
		$s = self::settings();
		if ( $s['passkey_primary'] && $this->user_is_covered( $user_id ) && $this->user_has_passkey( $user_id ) ) {
			return $this->webauthn_provider_key();
		}
		return $provider;
	}

	/** Strip weak fallbacks for covered users. */
	public function trim_providers( $providers, $user_id ) {
		$s = self::settings();
		if ( $s['disable_email'] && $this->user_is_covered( $user_id ) ) {
			$providers = array_diff( (array) $providers, array( self::P_EMAIL ) );
		}
		return $providers;
	}

	/** Nag, then redirect, covered users who have not enrolled a passkey. */
	public function enforce() {
		$s = self::settings();
		if ( ! $s['require_passkey'] || ! $this->dependencies_met() ) {
			return;
		}
		if ( wp_doing_ajax() || wp_doing_cron() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! $this->user_is_covered( $user ) || $this->user_has_passkey( $user->ID ) ) {
			return;
		}

		$since = (int) get_user_meta( $user->ID, '_pf_required_since', true );
		if ( ! $since ) {
			$since = time();
			update_user_meta( $user->ID, '_pf_required_since', $since );
		}
		$deadline = $since + $s['grace_days'] * DAY_IN_SECONDS;
		if ( time() < $deadline ) {
			return; // notice only, no redirect, during grace
		}

		$screen_ok = in_array( $GLOBALS['pagenow'] ?? '', array( 'profile.php', 'options.php', 'admin-ajax.php' ), true );
		if ( ! $screen_ok ) {
			wp_safe_redirect( admin_url( 'profile.php#two-factor-options' ) );
			exit;
		}
	}

	public function notices() {
		$s = self::settings();
		if ( ! $s['require_passkey'] || ! $this->dependencies_met() ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user->exists() || ! $this->user_is_covered( $user ) || $this->user_has_passkey( $user->ID ) ) {
			return;
		}
		$since    = (int) get_user_meta( $user->ID, '_pf_required_since', true );
		$deadline = $since ? $since + $s['grace_days'] * DAY_IN_SECONDS : 0;
		$left     = $deadline ? max( 0, $deadline - time() ) : 0;
		echo '<div class="notice notice-warning"><p>';
		if ( $left > 0 ) {
			printf(
				/* translators: 1: profile URL, 2: human time */
				wp_kses( __( 'This site requires administrators to sign in with a passkey. <a href="%1$s">Enrol one on your profile</a> — enforcement begins in %2$s.', 'passkey-first' ), array( 'a' => array( 'href' => array() ) ) ),
				esc_url( admin_url( 'profile.php#two-factor-options' ) ),
				esc_html( human_time_diff( time(), $deadline ) )
			);
		} else {
			printf(
				wp_kses( __( 'This site requires administrators to sign in with a passkey. <a href="%s">Enrol one on your profile</a> to regain full admin access.', 'passkey-first' ), array( 'a' => array( 'href' => array() ) ) ),
				esc_url( admin_url( 'profile.php#two-factor-options' ) )
			);
		}
		echo '</p></div>';
	}
}

Passkey_First::instance();
PF_Passwordless::instance();
