<?php
/**
 * Passwordless sign-in for Passkey First: ceremonies, storage, login UI.
 *
 * Copyright (C) 2026 Remy Mazmanian
 * GPL-2.0-or-later — see LICENSE.
 */

defined( 'ABSPATH' ) || exit;

final class PF_Passwordless {

	const META = '_pf_passkeys';

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
		add_action( 'admin_enqueue_scripts', array( $this, 'profile_assets' ) );

		add_action( 'login_enqueue_scripts', array( $this, 'login_assets' ) );
		add_action( 'login_form', array( $this, 'login_button' ) );

		add_filter( 'wp_authenticate_user', array( $this, 'maybe_block_password' ), 30 );
	}

	public static function mode() {
		return Passkey_First::settings()['pw_mode'] ?? 'off';
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

	/** Single use: read and burn. */
	private static function challenge_take( $id ) {
		$id = preg_replace( '/[^a-f0-9]/', '', (string) $id );
		$ch = get_transient( 'pf_ch_' . $id );
		delete_transient( 'pf_ch_' . $id );
		return is_array( $ch ) ? $ch : null;
	}

	/* ------------------------------------------------ enrolment */

	public function ajax_reg_options() {
		check_ajax_referer( 'pf_ceremony' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( 'not logged in', 403 );
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
			wp_send_json_error( 'not logged in', 403 );
		}
		$ch = self::challenge_take( $_POST['chal_id'] ?? '' );
		if ( ! $ch || (int) $ch['u'] !== $user->ID ) {
			wp_send_json_error( 'challenge expired — try again', 400 );
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
			wp_send_json_error( 'verification failed: ' . $e->getMessage(), 400 );
		}
		$list = self::credentials( $user->ID );
		foreach ( $list as $existing ) {
			if ( hash_equals( $existing['id'], $cred['cred_id'] ) ) {
				wp_send_json_error( 'this passkey is already enrolled', 400 );
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

	public function ajax_revoke() {
		check_ajax_referer( 'pf_ceremony' );
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			wp_send_json_error( 'not logged in', 403 );
		}
		$id   = (string) ( $_POST['cred_id'] ?? '' );
		$list = array_filter( self::credentials( $user->ID ), function ( $c ) use ( $id ) {
			return ! hash_equals( $c['id'], $id );
		} );
		self::save( $user->ID, $list );
		wp_send_json_success( array( 'remaining' => count( $list ) ) );
	}

	/* ------------------------------------------------ login */

	public function ajax_login_options() {
		$ch = self::challenge_create( 0 );
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
		$ch = self::challenge_take( $_POST['chal_id'] ?? '' );
		if ( ! $ch ) {
			wp_send_json_error( 'challenge expired — try again', 400 );
		}
		try {
			$uh = PF_WebAuthn::b64u_decode( (string) ( $_POST['uh'] ?? '' ) );
		} catch ( Exception $e ) {
			$uh = '';
		}
		if ( 4 !== strlen( $uh ) ) {
			wp_send_json_error( 'unrecognised passkey', 400 );
		}
		$uid  = unpack( 'N', $uh )[1];
		$user = get_userdata( $uid );
		if ( ! $user ) {
			wp_send_json_error( 'unrecognised passkey', 400 );
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
			wp_send_json_error( 'unrecognised passkey', 400 );
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
			wp_send_json_error( 'verification failed', 400 );
		}
		$list[ $found ]['count']     = $new_count;
		$list[ $found ]['last_used'] = time();
		self::save( $uid, $list );

		wp_set_auth_cookie( $uid, true );
		do_action( 'wp_login', $user->user_login, $user );
		wp_send_json_success( array( 'redirect' => admin_url() ) );
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
		if ( 'profile.php' !== $hook ) {
			return;
		}
		wp_enqueue_script( 'pf-profile', plugins_url( 'js/pf-profile.js', dirname( __FILE__ ) ), array(), '0.2.0', true );
		wp_localize_script( 'pf-profile', 'pfCfg', array(
			'ajax'  => admin_url( 'admin-ajax.php' ),
			'nonce' => wp_create_nonce( 'pf_ceremony' ),
		) );
	}

	public function profile_section( $user ) {
		if ( get_current_user_id() !== $user->ID ) {
			return;
		}
		$list = self::credentials( $user->ID );
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
				<button type="button" class="button" id="pf-enrol"><?php esc_html_e( 'Add a passkey', 'passkey-first' ); ?></button>
				<span id="pf-enrol-msg" style="margin-left:8px;color:#646970;"></span>
				<p class="description"><?php esc_html_e( 'A passkey signs you in with your fingerprint, face, or device PIN — no password typed. Enrol at least two (for example, phone and laptop) so losing one device never locks you out.', 'passkey-first' ); ?></p>
			</td>
		</tr></table>
		<?php
	}

	public function login_assets() {
		if ( 'off' === self::mode() ) {
			return;
		}
		wp_enqueue_script( 'pf-login', plugins_url( 'js/pf-login.js', dirname( __FILE__ ) ), array(), '0.2.0', true );
		wp_localize_script( 'pf-login', 'pfCfg', array(
			'ajax' => admin_url( 'admin-ajax.php' ),
		) );
	}

	public function login_button() {
		if ( 'off' === self::mode() ) {
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
