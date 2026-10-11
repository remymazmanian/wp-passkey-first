<?php
/**
 * Passwordless sign-in for Passkey First: ceremonies, storage, login UI.
 *
 * Copyright (C) 2026 Remy Mazmanian
 * GPL-2.0-or-later. See LICENSE.
 */

defined( 'ABSPATH' ) || exit;

final class PF_Passwordless {

	const META = '_pf_passkeys';

	/** Ties a sign-in challenge to the browser that asked for it (blocks login CSRF). */
	const CHALLENGE_COOKIE = 'pf_chal';

	/** Sign-in challenges one IP address may request per window. Filter: pf_login_rate_limit. */
	const RATE_LIMIT  = 30;
	const RATE_WINDOW = 300;

	private static $instance;

	public static function instance() {
		return self::$instance ?: self::$instance = new self();
	}

	private function __construct() {
		add_action( 'wp_ajax_pf_reg_options', array( $this, 'ajax_reg_options' ) );
		add_action( 'wp_ajax_pf_reg_finish', array( $this, 'ajax_reg_finish' ) );
		add_action( 'wp_ajax_pf_revoke', array( $this, 'ajax_revoke' ) );
		add_action( 'wp_ajax_pf_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_nopriv_pf_login_options', array( $this, 'ajax_login_options' ) );
		add_action( 'wp_ajax_pf_login_finish', array( $this, 'ajax_login_finish' ) );
		add_action( 'wp_ajax_nopriv_pf_login_finish', array( $this, 'ajax_login_finish' ) );

		add_action( 'show_user_profile', array( $this, 'profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'profile_assets' ) );

		add_action( 'login_enqueue_scripts', array( $this, 'login_assets' ) );
		add_action( 'login_form', array( $this, 'login_button' ) );

		add_filter( 'wp_authenticate_user', array( $this, 'maybe_block_password' ), 30 );
	}

	public static function mode() {
		return Passkey_First::settings()['pw_mode'] ?? 'off';
	}

	public static function enabled() {
		return 'off' !== self::mode();
	}

	/** Passkey sign-in is for covered roles only, and only while the feature is on. */
	public static function user_may_use( $user ) {
		return self::enabled() && Passkey_First::instance()->user_is_covered( $user );
	}

	/* ------------------------------------------------ storage */

	public static function credentials( $user_id ) {
		$list = get_user_meta( $user_id, self::META, true );
		return is_array( $list ) ? $list : array();
	}

	public static function has_passkey( $user_id ) {
		return (bool) self::credentials( $user_id );
	}

	private static function save( $user_id, $list ) {
		if ( ! $list ) {
			delete_user_meta( $user_id, self::META );
			return;
		}
		update_user_meta( $user_id, self::META, array_values( $list ) );
	}

	/* ------------------------------------------------ context */

	private static function rp_id() {
		return wp_parse_url( home_url(), PHP_URL_HOST );
	}

	private static function origins() {
		$out = array();
		foreach ( array( home_url(), site_url() ) as $u ) {
			$p     = wp_parse_url( $u );
			$out[] = $p['scheme'] . '://' . $p['host'] . ( isset( $p['port'] ) ? ':' . $p['port'] : '' );
		}
		return array_values( array_unique( $out ) );
	}

	private static function challenge_create( $user_id = 0 ) {
		$id        = bin2hex( random_bytes( 16 ) );
		$challenge = PF_WebAuthn::b64u_encode( random_bytes( 32 ) );
		set_transient( 'pf_ch_' . $id, array( 'c' => $challenge, 'u' => (int) $user_id ), 2 * MINUTE_IN_SECONDS );
		return array( 'id' => $id, 'challenge' => $challenge );
	}

	/**
	 * Single use: read and burn. Only the request whose delete succeeds gets the
	 * challenge, so two concurrent requests can't both spend it.
	 */
	private static function challenge_take( $id ) {
		$key = 'pf_ch_' . preg_replace( '/[^a-f0-9]/', '', (string) $id );
		$ch  = get_transient( $key );
		if ( ! is_array( $ch ) || ! delete_transient( $key ) ) {
			return null;
		}
		return $ch;
	}

	private static function set_challenge_cookie( $value, $expires ) {
		setcookie( self::CHALLENGE_COOKIE, $value, array(
			'expires'  => $expires,
			'path'     => COOKIEPATH ? COOKIEPATH : '/',
			'domain'   => COOKIE_DOMAIN,
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Strict',
		) );
	}

	private static function rate_limited() {
		$ip    = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
		$key   = 'pf_rl_' . md5( $ip . wp_salt( 'nonce' ) );
		$count = (int) get_transient( $key );
		$limit = (int) apply_filters( 'pf_login_rate_limit', self::RATE_LIMIT );
		if ( $count >= $limit ) {
			return true;
		}
		set_transient( $key, $count + 1, self::RATE_WINDOW );
		return false;
	}

	/* ------------------------------------------------ enrolment */

	public function ajax_reg_options() {
		check_ajax_referer( 'pf_ceremony' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( 'Not signed in.', 403 );
		}
		if ( ! self::user_may_use( $user ) ) {
			wp_send_json_error( __( 'Passkey sign-in isn\'t available for your account.', 'passkey-first' ), 403 );
		}
		$ch      = self::challenge_create( $user->ID );
		$exclude = array();
		foreach ( self::credentials( $user->ID ) as $cred ) {
			$exclude[] = array( 'type' => 'public-key', 'id' => $cred['id'] );
		}
		wp_send_json_success( array(
			'chal_id' => $ch['id'],
			'publicKey' => array(
				'rp'        => array( 'id' => self::rp_id(), 'name' => get_bloginfo( 'name' ) ),
				'user'      => array(
					'id'          => PF_WebAuthn::b64u_encode( pack( 'N', $user->ID ) ),
					'name'        => $user->user_login,
					'displayName' => $user->display_name,
				),
				'challenge' => $ch['challenge'],
				'pubKeyCredParams' => array(
					array( 'type' => 'public-key', 'alg' => -7 ),
					array( 'type' => 'public-key', 'alg' => -257 ),
				),
				'authenticatorSelection' => array(
					'residentKey'      => 'required',
					'userVerification' => 'required',
				),
				'attestation'        => 'none',
				'excludeCredentials' => $exclude,
				'timeout'            => 60000,
			),
		) );
	}

	public function ajax_reg_finish() {
		check_ajax_referer( 'pf_ceremony' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( 'Not signed in.', 403 );
		}
		if ( ! self::user_may_use( $user ) ) {
			wp_send_json_error( __( 'Passkey sign-in isn\'t available for your account.', 'passkey-first' ), 403 );
		}
		$ch = self::challenge_take( $_POST['chal_id'] ?? '' );
		if ( ! $ch || (int) $ch['u'] !== $user->ID ) {
			wp_send_json_error( __( 'That took too long. Try again.', 'passkey-first' ), 400 );
		}
		try {
			$cred = PF_WebAuthn::verify_registration(
				(string) ( $_POST['att'] ?? '' ),
				(string) ( $_POST['cdj'] ?? '' ),
				$ch['c'],
				self::rp_id(),
				self::origins()
			);
		} catch ( Exception $e ) {
			wp_send_json_error( 'Verification failed: ' . $e->getMessage(), 400 );
		}
		$list = self::credentials( $user->ID );
		foreach ( $list as $existing ) {
			if ( hash_equals( $existing['id'], $cred['cred_id'] ) ) {
				wp_send_json_error( __( 'This passkey is already enrolled.', 'passkey-first' ), 400 );
			}
		}
		$list[] = array(
			'id'        => $cred['cred_id'],
			'pem'       => $cred['pem'],
			'alg'       => $cred['alg'],
			'count'     => $cred['count'],
			'label'     => sanitize_text_field( wp_unslash( $_POST['label'] ?? '' ) ) ?: __( 'Passkey', 'passkey-first' ),
			'created'   => time(),
			'last_used' => 0,
		);
		self::save( $user->ID, $list );
		wp_send_json_success( array( 'enrolled' => count( $list ) ) );
	}

	/** Removes one passkey: your own, or another user's if you may edit that user. */
	public function ajax_revoke() {
		check_ajax_referer( 'pf_ceremony' );
		$current = wp_get_current_user();
		if ( ! $current->exists() ) {
			wp_send_json_error( 'Not signed in.', 403 );
		}
		$user_id = isset( $_POST['user_id'] ) ? (int) $_POST['user_id'] : $current->ID;
		if ( $user_id !== $current->ID && ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( __( 'You can\'t remove passkeys for this user.', 'passkey-first' ), 403 );
		}
		$id   = (string) ( $_POST['cred_id'] ?? '' );
		$list = array_filter( self::credentials( $user_id ), function ( $c ) use ( $id ) {
			return ! hash_equals( $c['id'], $id );
		} );
		self::save( $user_id, $list );
		wp_send_json_success( array( 'remaining' => count( $list ) ) );
	}

	/* ------------------------------------------------ login */

	public function ajax_login_options() {
		if ( ! self::enabled() ) {
			wp_send_json_error( __( 'Passkey sign-in is turned off.', 'passkey-first' ), 403 );
		}
		if ( self::rate_limited() ) {
			wp_send_json_error( __( 'Too many attempts. Wait a few minutes and try again.', 'passkey-first' ), 429 );
		}
		$ch = self::challenge_create( 0 );
		self::set_challenge_cookie( $ch['id'], time() + 2 * MINUTE_IN_SECONDS );
		wp_send_json_success( array(
			'chal_id'   => $ch['id'],
			'publicKey' => array(
				'rpId'             => self::rp_id(),
				'challenge'        => $ch['challenge'],
				'userVerification' => 'required',
				'allowCredentials' => array(),
				'timeout'          => 60000,
			),
		) );
	}

	public function ajax_login_finish() {
		if ( ! self::enabled() ) {
			wp_send_json_error( __( 'Passkey sign-in is turned off.', 'passkey-first' ), 403 );
		}
		$chal_id = (string) ( $_POST['chal_id'] ?? '' );
		$cookie  = (string) ( $_COOKIE[ self::CHALLENGE_COOKIE ] ?? '' );
		self::set_challenge_cookie( '', time() - YEAR_IN_SECONDS );
		// The challenge must come back from the browser that requested it.
		if ( '' === $cookie || ! hash_equals( $cookie, $chal_id ) ) {
			wp_send_json_error( __( 'That took too long. Try again.', 'passkey-first' ), 400 );
		}
		$ch = self::challenge_take( $chal_id );
		if ( ! $ch ) {
			wp_send_json_error( __( 'That took too long. Try again.', 'passkey-first' ), 400 );
		}
		try {
			$uh = PF_WebAuthn::b64u_decode( (string) ( $_POST['uh'] ?? '' ) );
		} catch ( Exception $e ) {
			$uh = '';
		}
		if ( 4 !== strlen( $uh ) ) {
			wp_send_json_error( __( 'Unrecognised passkey.', 'passkey-first' ), 400 );
		}
		$uid  = unpack( 'N', $uh )[1];
		$user = get_userdata( $uid );
		if ( ! $user ) {
			wp_send_json_error( __( 'Unrecognised passkey.', 'passkey-first' ), 400 );
		}
		$raw_id = (string) ( $_POST['id'] ?? '' );
		$list   = self::credentials( $uid );
		$found  = null;
		foreach ( $list as $i => $cred ) {
			if ( hash_equals( $cred['id'], $raw_id ) ) {
				$found = $i;
				break;
			}
		}
		if ( null === $found ) {
			wp_send_json_error( __( 'Unrecognised passkey.', 'passkey-first' ), 400 );
		}
		try {
			$new_count = PF_WebAuthn::verify_assertion(
				(string) ( $_POST['ad'] ?? '' ),
				(string) ( $_POST['cdj'] ?? '' ),
				(string) ( $_POST['sig'] ?? '' ),
				$list[ $found ],
				$ch['c'],
				self::rp_id(),
				self::origins()
			);
		} catch ( Exception $e ) {
			wp_send_json_error( __( 'Verification failed.', 'passkey-first' ), 400 );
		}

		if ( ! self::user_may_use( $user ) ) {
			wp_send_json_error( __( 'Passkey sign-in isn\'t available for this account.', 'passkey-first' ), 403 );
		}
		$allowed = self::account_allowed( $user );
		if ( is_wp_error( $allowed ) ) {
			wp_send_json_error( wp_strip_all_tags( $allowed->get_error_message() ), 403 );
		}

		$list[ $found ]['count']     = $new_count;
		$list[ $found ]['last_used'] = time();
		self::save( $uid, $list );

		self::complete_login( $user, ! empty( $_POST['remember'] ) );

		$requested = wp_unslash( (string) ( $_POST['redirect_to'] ?? '' ) );
		$redirect  = '' !== $requested ? wp_validate_redirect( $requested, admin_url() ) : admin_url();
		$redirect  = wp_validate_redirect( (string) apply_filters( 'login_redirect', $redirect, $requested, $user ), admin_url() );
		wp_send_json_success( array( 'redirect' => '' !== $redirect ? $redirect : admin_url() ) );
	}

	/**
	 * The account checks a password sign-in would get: spam flags on multisite,
	 * and anything hooked to wp_authenticate_user (lockouts, disabled accounts).
	 */
	private static function account_allowed( WP_User $user ) {
		if ( is_multisite() && is_user_spammy( $user ) ) {
			return new WP_Error( 'pf_spammy', __( 'This account has been marked as spam.', 'passkey-first' ) );
		}
		$result = apply_filters( 'wp_authenticate_user', $user, '' );
		return is_wp_error( $result ) ? $result : true;
	}

	/**
	 * Signs the user in. A passkey with user verification is already two
	 * factors (the device, plus the fingerprint, face or PIN that unlocks it),
	 * so the Two Factor plugin is told this login has passed: the session is
	 * marked as two-factor authenticated, and Two Factor's wp_login handler,
	 * which would otherwise clear the cookie and show its own prompt, is
	 * skipped for this one login.
	 */
	private static function complete_login( WP_User $user, $remember ) {
		$mark_session = function ( $session ) {
			$session['two-factor-login'] = time();
			return $session;
		};
		add_filter( 'attach_session_information', $mark_session );
		wp_set_auth_cookie( $user->ID, $remember );
		remove_filter( 'attach_session_information', $mark_session );

		// Two Factor 0.17+ asks this filter; older versions only check for a primary provider.
		$not_required = function ( $required, $u = null ) use ( $user ) {
			return ( $u instanceof WP_User && $u->ID === $user->ID ) ? false : $required;
		};
		$no_provider = function ( $provider, $user_id = 0 ) use ( $user ) {
			return (int) $user_id === $user->ID ? null : $provider;
		};
		add_filter( 'two_factor_is_required_for_user', $not_required, PHP_INT_MAX, 2 );
		add_filter( 'two_factor_primary_provider_for_user', $no_provider, PHP_INT_MAX, 2 );
		do_action( 'wp_login', $user->user_login, $user );
		remove_filter( 'two_factor_is_required_for_user', $not_required, PHP_INT_MAX );
		remove_filter( 'two_factor_primary_provider_for_user', $no_provider, PHP_INT_MAX );
	}

	/* ------------------------------------------------ password policy */

	/**
	 * In "required" mode, covered users who hold a passkey may no longer
	 * sign in with a password on the interactive login form. Application
	 * Passwords, REST and XML-RPC are untouched; wp-cli always works;
	 * define PF_ALLOW_PASSWORDS in wp-config.php as a break-glass.
	 */
	public function maybe_block_password( $user ) {
		if ( is_wp_error( $user ) || ! $user instanceof WP_User ) {
			return $user;
		}
		if ( 'required' !== self::mode() || defined( 'PF_ALLOW_PASSWORDS' ) ) {
			return $user;
		}
		if ( ! did_action( 'login_init' ) ) {
			return $user; // not the interactive login form
		}
		if ( ! Passkey_First::instance()->user_is_covered( $user ) || ! self::has_passkey( $user->ID ) ) {
			return $user;
		}
		return new WP_Error(
			'pf_passwordless_required',
			__( 'Password sign-in is disabled for this account. Use the "Sign in with a passkey" button.', 'passkey-first' )
		);
	}

	/* ------------------------------------------------ UI */

	public function profile_assets( $hook ) {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}
		$user_id = 'user-edit.php' === $hook && isset( $_GET['user_id'] ) ? (int) $_GET['user_id'] : get_current_user_id();
		wp_enqueue_script( 'pf-profile', plugins_url( 'js/pf-profile.js', dirname( __FILE__ ) ), array(), PF_VERSION, true );
		wp_localize_script( 'pf-profile', 'pfCfg', array(
			'ajax'   => admin_url( 'admin-ajax.php' ),
			'nonce'  => wp_create_nonce( 'pf_ceremony' ),
			'userId' => $user_id,
		) );
	}

	public function profile_section( $user ) {
		$own = get_current_user_id() === $user->ID;
		if ( ! $own && ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$list = self::credentials( $user->ID );
		if ( ! $own && ! $list ) {
			return; // nothing for an administrator to manage
		}
		?>
		<h2 id="pf-passkeys"><?php esc_html_e( 'Passkeys', 'passkey-first' ); ?></h2>
		<table class="form-table" role="presentation"><tr>
			<th><?php esc_html_e( 'Passwordless sign-in', 'passkey-first' ); ?></th>
			<td>
				<?php if ( $list ) : ?>
				<table style="border-collapse:collapse;margin-bottom:10px;">
					<?php foreach ( $list as $cred ) : ?>
					<tr>
						<td style="padding:4px 16px 4px 0;"><strong><?php echo esc_html( $cred['label'] ); ?></strong></td>
						<td style="padding:4px 16px 4px 0;color:#646970;">
							<?php echo esc_html( sprintf(
								/* translators: 1: date, 2: relative time */
								__( 'added %1$s · last used %2$s', 'passkey-first' ),
								wp_date( get_option( 'date_format' ), $cred['created'] ),
								$cred['last_used'] ? human_time_diff( $cred['last_used'] ) . ' ' . __( 'ago', 'passkey-first' ) : __( 'never', 'passkey-first' )
							) ); ?>
						</td>
						<td><button type="button" class="button-link-delete pf-revoke" data-id="<?php echo esc_attr( $cred['id'] ); ?>"><?php esc_html_e( 'Remove', 'passkey-first' ); ?></button></td>
					</tr>
					<?php endforeach; ?>
				</table>
				<?php endif; ?>
				<?php if ( ! $own ) : ?>
					<p class="description"><?php esc_html_e( 'Remove a passkey if its device is lost or this person should no longer sign in with it.', 'passkey-first' ); ?></p>
				<?php elseif ( ! self::enabled() ) : ?>
					<p class="description"><?php esc_html_e( 'Passkey sign-in is turned off on this site.', 'passkey-first' ); ?></p>
				<?php elseif ( ! self::user_may_use( $user ) ) : ?>
					<p class="description"><?php esc_html_e( 'Passkey sign-in isn\'t available for your role on this site.', 'passkey-first' ); ?></p>
				<?php else : ?>
					<button type="button" class="button" id="pf-enrol"><?php esc_html_e( 'Add a passkey', 'passkey-first' ); ?></button>
					<span id="pf-enrol-msg" style="margin-left:8px;color:#646970;"></span>
					<p class="description"><?php esc_html_e( 'A passkey signs you in with your fingerprint, face, or device PIN, with no password to type. Enrol at least two (for example, phone and laptop) so losing one device never locks you out.', 'passkey-first' ); ?></p>
				<?php endif; ?>
			</td>
		</tr></table>
		<?php
	}

	public function login_assets() {
		if ( ! self::enabled() ) {
			return;
		}
		wp_enqueue_script( 'pf-login', plugins_url( 'js/pf-login.js', dirname( __FILE__ ) ), array(), PF_VERSION, true );
		wp_localize_script( 'pf-login', 'pfCfg', array(
			'ajax' => admin_url( 'admin-ajax.php' ),
		) );
	}

	public function login_button() {
		if ( ! self::enabled() ) {
			return;
		}
		?>
		<div id="pf-login-wrap" style="margin:0 0 16px;">
			<button type="button" class="button button-primary button-large" id="pf-login" style="width:100%;">
				<?php esc_html_e( 'Sign in with a passkey', 'passkey-first' ); ?>
			</button>
			<div id="pf-login-msg" style="margin-top:8px;color:#b32d2e;"></div>
		</div>
		<?php
	}
}
