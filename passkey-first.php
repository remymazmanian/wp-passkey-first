<?php
/**
 * Plugin Name: Passkey First
 * Plugin URI: https://remymazmanian.com/
 * Description: Passkey-first two-factor policy for administrators. Coordinates the Two Factor plugin and its WebAuthn provider: makes the passkey the primary prompt, can require enrolment for chosen roles with a grace period, and can retire weaker fallbacks.
 * Version: 0.1.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: Remy Mazmanian
 * Author URI: https://remymazmanian.com/
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: passkey-first
 */

defined( 'ABSPATH' ) || exit;

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
				return $out;
			},
		) );
	}

	public function add_settings_page() {
		add_options_page( 'Passkey First', 'Passkey First', 'manage_options', 'passkey-first', array( $this, 'render_settings_page' ) );
	}

	public function render_settings_page() {
		$s = self::settings();
		?>
		<div class="wrap">
			<h1>Passkey First</h1>
			<?php if ( ! $this->dependencies_met() ) : ?>
				<div class="notice notice-error"><p>
					<?php esc_html_e( 'Passkey First needs the "Two Factor" plugin and the "WebAuthn Provider for Two Factor" plugin, both active. Nothing is enforced until they are.', 'passkey-first' ); ?>
				</p></div>
			<?php endif; ?>
			<form method="post" action="options.php">
				<?php settings_fields( 'passkey_first' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e( 'Covered roles', 'passkey-first' ); ?></th>
						<td>
							<?php foreach ( get_editable_roles() as $slug => $role ) : ?>
								<label style="display:block">
									<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[roles][]" value="<?php echo esc_attr( $slug ); ?>" <?php checked( in_array( $slug, $s['roles'], true ) ); ?>>
									<?php echo esc_html( translate_user_role( $role['name'] ) ); ?>
								</label>
							<?php endforeach; ?>
							<p class="description"><?php esc_html_e( 'The policy applies to users holding any of these roles.', 'passkey-first' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Passkey is the primary prompt', 'passkey-first' ); ?></th>
						<td><label>
							<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[passkey_primary]" value="1" <?php checked( $s['passkey_primary'] ); ?>>
							<?php esc_html_e( 'When a covered user has a passkey enrolled, ask for it first at login.', 'passkey-first' ); ?>
						</label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Require a passkey', 'passkey-first' ); ?></th>
						<td>
							<label>
								<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[require_passkey]" value="1" <?php checked( $s['require_passkey'] ); ?>>
								<?php esc_html_e( 'Covered users must enrol a passkey. Until they do, wp-admin nags and, after the grace period, redirects them to their profile to enrol.', 'passkey-first' ); ?>
							</label>
							<p class="description"><?php esc_html_e( 'Enrol your own passkey before switching this on.', 'passkey-first' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Grace period', 'passkey-first' ); ?></th>
						<td>
							<input type="number" min="0" max="90" name="<?php echo esc_attr( self::OPTION ); ?>[grace_days]" value="<?php echo esc_attr( $s['grace_days'] ); ?>" class="small-text">
							<?php esc_html_e( 'days before the redirect kicks in. 0 enforces immediately.', 'passkey-first' ); ?>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Retire email codes', 'passkey-first' ); ?></th>
						<td><label>
							<input type="checkbox" name="<?php echo esc_attr( self::OPTION ); ?>[disable_email]" value="1" <?php checked( $s['disable_email'] ); ?>>
							<?php esc_html_e( 'Remove the email-code fallback for covered users. Email 2FA is only as strong as the mailbox.', 'passkey-first' ); ?>
						</label></td>
					</tr>
				</table>
				<?php submit_button(); ?>
			</form>
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
