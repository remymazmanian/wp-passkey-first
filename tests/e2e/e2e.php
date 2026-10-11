<?php
/**
 * End-to-end tests against a real WordPress with Two Factor installed.
 * Run through tests/e2e/run.sh, which starts the site in Docker.
 *
 * Env: PF_BASE (site URL), PF_WP_CLI (command prefix that runs WP-CLI).
 *
 * Copyright (C) 2026 Remy Mazmanian
 * GPL-2.0-or-later. See LICENSE.
 */

require __DIR__ . '/../lib/soft-authenticator.php';

$base   = rtrim( getenv( 'PF_BASE' ) ?: 'http://localhost:8088', '/' );
$cli    = getenv( 'PF_WP_CLI' ) ?: 'docker compose -f ' . escapeshellarg( __DIR__ . '/compose.yml' ) . ' run --rm -T cli';
$rp     = parse_url( $base, PHP_URL_HOST );
$ajax   = "$base/wp-admin/admin-ajax.php";
$passed = 0;
$failed = 0;

function wp( ...$args ) {
	global $cli;
	$out = shell_exec( $cli . ' ' . implode( ' ', array_map( 'escapeshellarg', $args ) ) . ' 2>/dev/null' );
	return trim( str_replace( "\r", '', (string) $out ) );
}

function settings( $overrides ) {
	$s = array_merge( array( 'roles' => array( 'administrator' ), 'passkey_primary' => 1, 'require_passkey' => 0, 'grace_days' => 7, 'disable_email' => 0, 'pw_mode' => 'optional' ), $overrides );
	wp( 'option', 'update', 'passkey_first_settings', json_encode( $s ), '--format=json' );
}

function http( $url, $post = null, $cookies = array() ) {
	$ch = curl_init( $url );
	curl_setopt_array( $ch, array( CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_FOLLOWLOCATION => false ) );
	if ( $cookies ) {
		curl_setopt( $ch, CURLOPT_COOKIE, implode( '; ', array_map( function ( $k, $v ) { return "$k=$v"; }, array_keys( $cookies ), $cookies ) ) );
	}
	if ( null !== $post ) {
		curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query( $post ) );
	}
	$raw  = curl_exec( $ch );
	$size = curl_getinfo( $ch, CURLINFO_HEADER_SIZE );
	$head = substr( $raw, 0, $size );
	$set  = array();
	preg_match_all( '/^set-cookie:\s*([^=]+)=([^;]*)(.*)$/mi', $head, $m, PREG_SET_ORDER );
	foreach ( $m as $c ) {
		$expired = preg_match( '/expires=([^;]+)/i', $c[3], $e ) && strtotime( $e[1] ) < time();
		$set[ trim( $c[1] ) ] = ( $expired || '' === trim( $c[2] ) ) ? null : $c[2];
	}
	return array(
		'code'    => curl_getinfo( $ch, CURLINFO_HTTP_CODE ),
		'body'    => substr( $raw, $size ),
		'json'    => json_decode( substr( $raw, $size ), true ),
		'cookies' => $set,
		'location' => preg_match( '/^location:\s*(\S+)/mi', $head, $l ) ? $l[1] : '',
	);
}

/** Auth cookies for a user, minted through WP-CLI (no password needed). */
function cookies_for( $user_id ) {
	$out = wp( 'eval', '$t = WP_Session_Tokens::get_instance(' . (int) $user_id . ')->create(time()+3600); echo AUTH_COOKIE."=".wp_generate_auth_cookie(' . (int) $user_id . ', time()+3600, "auth", $t)."\n".LOGGED_IN_COOKIE."=".wp_generate_auth_cookie(' . (int) $user_id . ', time()+3600, "logged_in", $t);' );
	$cookies = array();
	foreach ( explode( "\n", $out ) as $line ) {
		list( $k, $v ) = explode( '=', $line, 2 );
		$cookies[ $k ] = $v;
	}
	return $cookies;
}

function nonce_for( $cookies ) {
	global $base;
	$r = http( "$base/wp-admin/profile.php", null, $cookies );
	return preg_match( '/pfCfg = \{[^}]*"nonce":"([a-f0-9]+)"/', $r['body'], $m ) ? $m[1] : '';
}

/** Enrols a new software passkey for the user. Returns array( response, credential ). */
function enrol( $user_id ) {
	global $ajax, $rp, $base;
	$cookies = cookies_for( $user_id );
	$nonce   = nonce_for( $cookies );
	$opt     = http( $ajax, array( 'action' => 'pf_reg_options', '_ajax_nonce' => $nonce ), $cookies );
	$cred    = PF_Soft_Authenticator::credential( -7 );
	if ( empty( $opt['json']['success'] ) ) {
		return array( $opt, $cred );
	}
	$reg = PF_Soft_Authenticator::register( $cred, $rp, $base, $opt['json']['data']['publicKey']['challenge'], $user_id );
	$fin = http( $ajax, array( 'action' => 'pf_reg_finish', '_ajax_nonce' => $nonce, 'chal_id' => $opt['json']['data']['chal_id'], 'att' => $reg['att'], 'cdj' => $reg['cdj'], 'label' => 'soft' ), $cookies );
	return array( $fin, $cred );
}

/**
 * Signs in with a passkey. $o: send_cookie (default true), assert (options for
 * the authenticator), extra (extra POST fields), replay (re-send this response).
 */
function sign_in( &$cred, $user_id, $o = array() ) {
	global $ajax, $rp, $base;
	$opt = http( $ajax, array( 'action' => 'pf_login_options' ) );
	if ( empty( $opt['json']['success'] ) ) {
		return array( 'stage' => 'options', 'r' => $opt );
	}
	$jar  = ( $o['send_cookie'] ?? true ) ? array_filter( $opt['cookies'] ) : array();
	$a    = PF_Soft_Authenticator::assert( $cred, $rp, $base, $opt['json']['data']['publicKey']['challenge'], $user_id, $o['assert'] ?? array() );
	$post = array( 'action' => 'pf_login_finish', 'chal_id' => $opt['json']['data']['chal_id'] ) + $a + ( $o['extra'] ?? array() );
	$fin  = http( $ajax, $post, $jar );
	$logged_in = array_filter( $fin['cookies'], function ( $v, $k ) { return 0 === strpos( $k, 'wordpress_' ) && null !== $v; }, ARRAY_FILTER_USE_BOTH );
	$admin = $logged_in ? http( "$base/wp-admin/", null, $logged_in ) : null;
	return array( 'stage' => 'finish', 'r' => $fin, 'post' => $post, 'jar' => $jar, 'admin_ok' => $admin && 200 === $admin['code'] );
}

function check( $name, $cond, $detail = '' ) {
	global $passed, $failed;
	if ( $cond ) {
		$passed++;
		echo "PASS  $name\n";
	} else {
		$failed++;
		echo "FAIL  $name" . ( $detail ? "  ($detail)" : '' ) . "\n";
	}
}

function brief( $s ) {
	$r = $s['r'];
	return 'HTTP ' . $r['code'] . ' ' . ( null !== $r['json'] ? json_encode( $r['json'] ) : 'non-JSON: ' . substr( trim( $r['body'] ), 0, 60 ) );
}

/* ------------------------------------------------------------------ setup */

wp( 'eval', 'wp_mkdir_p( WPMU_PLUGIN_DIR ); file_put_contents( WPMU_PLUGIN_DIR . "/pf-test.php", "<?php\nadd_filter( \"wp_authenticate_user\", function ( \$u ) { return ( \$u instanceof WP_User && get_user_meta( \$u->ID, \"pf_test_blocked\", true ) ) ? new WP_Error( \"pf_test\", \"This account is locked.\" ) : \$u; }, 5 );\nadd_filter( \"pf_login_rate_limit\", function ( \$l ) { return (int) get_option( \"pf_test_rate_limit\", \$l ); } );\n" );' );
wp( 'transient', 'delete', '--all' );
wp( 'user', 'meta', 'delete', '1', '_pf_passkeys' );
wp( 'user', 'meta', 'delete', '1', '_two_factor_enabled_providers' );
wp( 'user', 'meta', 'delete', '1', '_two_factor_provider' );
$editor = (int) wp( 'user', 'get', 'pf-editor', '--field=ID' );
if ( ! $editor ) {
	$editor = (int) wp( 'user', 'create', 'pf-editor', 'pf-editor@example.test', '--role=editor', '--user_pass=pf-editor-test-pass', '--porcelain' );
}
wp( 'user', 'meta', 'delete', (string) $editor, '_pf_passkeys' );
settings( array() );

/* ------------------------------------------------------------------ enrolment and sign-in */

list( $r, $admin_cred ) = enrol( 1 );
check( 'covered admin can enrol a passkey', ! empty( $r['json']['success'] ), json_encode( $r['json'] ) );

$s = sign_in( $admin_cred, 1 );
check( 'admin signs in with the passkey', ! empty( $s['r']['json']['success'] ) && $s['admin_ok'], brief( $s ) );
check( 'default redirect is wp-admin', ( $s['r']['json']['data']['redirect'] ?? '' ) === "$base/wp-admin/" );

$replay = http( $ajax, $s['post'], $s['jar'] );
check( 'replaying a used sign-in response is refused', 400 === $replay['code'] && empty( $replay['json']['success'] ), 'HTTP ' . $replay['code'] );

wp( 'user', 'meta', 'update', '1', '_two_factor_enabled_providers', '["Two_Factor_Email"]', '--format=json' );
wp( 'user', 'meta', 'update', '1', '_two_factor_provider', 'Two_Factor_Email' );
$s = sign_in( $admin_cred, 1 );
check( 'admin with Two Factor turned on signs in with the passkey', ! empty( $s['r']['json']['success'] ) && $s['admin_ok'], brief( $s ) );
$marked = wp( 'eval', '$s = get_user_meta(1, "session_tokens", true); $last = is_array($s) ? end($s) : array(); echo empty($last["two-factor-login"]) ? "no" : "yes";' );
check( 'the passkey session is marked as two-factor authenticated', 'yes' === $marked, $marked );
wp( 'user', 'meta', 'delete', '1', '_two_factor_enabled_providers' );
wp( 'user', 'meta', 'delete', '1', '_two_factor_provider' );

$s = sign_in( $admin_cred, 1, array( 'extra' => array( 'redirect_to' => "$base/wp-admin/edit.php" ) ) );
check( 'a same-site redirect_to is honoured', ( $s['r']['json']['data']['redirect'] ?? '' ) === "$base/wp-admin/edit.php", brief( $s ) );
$s = sign_in( $admin_cred, 1, array( 'extra' => array( 'redirect_to' => 'https://evil.example/' ) ) );
check( 'an off-site redirect_to falls back to wp-admin', ( $s['r']['json']['data']['redirect'] ?? '' ) === "$base/wp-admin/", brief( $s ) );

$s = sign_in( $admin_cred, 1, array( 'send_cookie' => false ) );
check( 'a sign-in without the browser\'s challenge cookie is refused (login CSRF)', 400 === $s['r']['code'] && ! $s['admin_ok'], brief( $s ) );

$s = sign_in( $admin_cred, 1, array( 'assert' => array( 'count' => 1 ) ) );
check( 'a sign-in counter that goes backwards is refused (cloned passkey)', 400 === $s['r']['code'] && ! $s['admin_ok'], brief( $s ) );

wp( 'user', 'meta', 'update', '1', 'pf_test_blocked', '1' );
$s = sign_in( $admin_cred, 1 );
check( 'an account blocked by another plugin can\'t sign in with a passkey', 403 === $s['r']['code'] && false !== strpos( (string) ( $s['r']['json']['data'] ?? '' ), 'locked' ) && ! $s['admin_ok'], brief( $s ) );
wp( 'user', 'meta', 'delete', '1', 'pf_test_blocked' );

/* ------------------------------------------------------------------ role scope and Off */

settings( array( 'roles' => array( 'editor' ) ) );
$s = sign_in( $admin_cred, 1 );
check( 'a user outside the covered roles can\'t sign in with a passkey', 403 === $s['r']['code'] && ! $s['admin_ok'], brief( $s ) );
list( $r ) = enrol( 1 );
check( 'a user outside the covered roles can\'t enrol', 403 === $r['code'], 'HTTP ' . $r['code'] );

settings( array( 'pw_mode' => 'off' ) );
$s = sign_in( $admin_cred, 1 );
check( 'with passwordless Off, sign-in is refused even with an enrolled passkey', 'options' === $s['stage'] && 403 === $s['r']['code'], brief( $s ) );
$direct = http( $ajax, array( 'action' => 'pf_login_finish', 'chal_id' => 'x' ) );
check( 'with passwordless Off, the finish endpoint is refused too', 403 === $direct['code'], 'HTTP ' . $direct['code'] );
$login = http( "$base/wp-login.php" );
check( 'with passwordless Off, the login page has no passkey button', false === strpos( $login['body'], 'pf-login' ) );
settings( array() );
$login = http( "$base/wp-login.php" );
check( 'with passwordless Optional, the login page shows the passkey button', false !== strpos( $login['body'], 'id="pf-login"' ) );

/* ------------------------------------------------------------------ admin management */

settings( array( 'roles' => array( 'administrator', 'editor' ) ) );
list( $r, $editor_cred ) = enrol( $editor );
check( 'a covered editor can enrol', ! empty( $r['json']['success'] ), json_encode( $r['json'] ) );
$editor_cookies = cookies_for( $editor );
$creds_admin    = json_decode( wp( 'user', 'meta', 'get', '1', '_pf_passkeys', '--format=json' ), true );
$r = http( $ajax, array( 'action' => 'pf_revoke', '_ajax_nonce' => nonce_for( $editor_cookies ), 'user_id' => 1, 'cred_id' => $creds_admin[0]['id'] ), $editor_cookies );
check( 'an editor can\'t remove an administrator\'s passkey', 403 === $r['code'] && count( json_decode( wp( 'user', 'meta', 'get', '1', '_pf_passkeys', '--format=json' ), true ) ) === 1, 'HTTP ' . $r['code'] );
$admin_cookies = cookies_for( 1 );
$creds_editor  = json_decode( wp( 'user', 'meta', 'get', (string) $editor, '_pf_passkeys', '--format=json' ), true );
$edit_page     = http( "$base/wp-admin/user-edit.php?user_id=$editor", null, $admin_cookies );
check( 'an administrator sees the editor\'s passkeys on their profile', false !== strpos( $edit_page['body'], 'pf-revoke' ) );
preg_match( '/pfCfg = \{[^}]*"nonce":"([a-f0-9]+)"/', $edit_page['body'], $m );
$r = http( $ajax, array( 'action' => 'pf_revoke', '_ajax_nonce' => $m[1] ?? '', 'user_id' => $editor, 'cred_id' => $creds_editor[0]['id'] ), $admin_cookies );
check( 'an administrator can remove the editor\'s passkey', ! empty( $r['json']['success'] ) && '' === wp( 'user', 'meta', 'get', (string) $editor, '_pf_passkeys' ), json_encode( $r['json'] ) );
$s = sign_in( $editor_cred, $editor );
check( 'a removed passkey no longer signs in', 400 === $s['r']['code'] && ! $s['admin_ok'], brief( $s ) );

/* ------------------------------------------------------------------ required mode */

list( $r, $editor_cred ) = enrol( $editor );
settings( array( 'roles' => array( 'administrator', 'editor' ), 'pw_mode' => 'required' ) );
$pw = http( "$base/wp-login.php", array( 'log' => 'pf-editor', 'pwd' => 'pf-editor-test-pass', 'wp-submit' => 'Log In', 'testcookie' => '1' ), array( 'wordpress_test_cookie' => 'WP+Cookie+check' ) );
check( 'Required mode blocks password sign-in for a covered user with a passkey', false !== strpos( $pw['body'], 'Password sign-in is disabled' ), 'HTTP ' . $pw['code'] . ' ' . $pw['location'] );
$s = sign_in( $editor_cred, $editor );
check( 'Required mode still allows the passkey', ! empty( $s['r']['json']['success'] ) && $s['admin_ok'], brief( $s ) );
settings( array() );

/* ------------------------------------------------------------------ rate limit */

wp( 'transient', 'delete', '--all' );
wp( 'option', 'update', 'pf_test_rate_limit', '3' );
$codes = array();
for ( $i = 0; $i < 4; $i++ ) {
	$codes[] = http( $ajax, array( 'action' => 'pf_login_options' ) )['code'];
}
check( 'sign-in challenges are rate limited per IP', array( 200, 200, 200, 429 ) === $codes, implode( ',', $codes ) );
wp( 'option', 'delete', 'pf_test_rate_limit' );
wp( 'transient', 'delete', '--all' );

/* ------------------------------------------------------------------ uninstall */

wp( 'eval', 'define( "WP_UNINSTALL_PLUGIN", "passkey-first/passkey-first.php" ); include WP_PLUGIN_DIR . "/passkey-first/uninstall.php";' );
check( 'uninstalling removes stored passkeys', '' === wp( 'user', 'meta', 'get', '1', '_pf_passkeys' ) && '' === wp( 'user', 'meta', 'get', (string) $editor, '_pf_passkeys' ) );
settings( array() );

echo "\n$passed passed, $failed failed\n";
exit( $failed ? 1 : 0 );
