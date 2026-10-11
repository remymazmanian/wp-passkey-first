<?php
// Standalone verifier test, no WordPress needed: php tests/run-verifier-tests.php
define( 'ABSPATH', '/' );
require __DIR__ . '/../includes/class-pf-webauthn.php';
require __DIR__ . '/lib/soft-authenticator.php';
// A PHP warning or notice means some input wasn't handled cleanly: count it as a failure.
set_error_handler( function ( $no, $msg, $file, $line ) {
	throw new ErrorException( "PHP warning: $msg at " . basename( $file ) . ":$line", 0, $no, $file, $line );
} );
$fx = json_decode( file_get_contents( __DIR__ . '/fixtures/es256.json' ), true );
$origins = array( $fx['origin'] );
$pass = 0; $fail = 0;
function t( $name, $fn, $expect_ok = true ) {
	global $pass, $fail;
	try { $fn(); $ok = true; $err = ''; }
	catch ( Exception $e ) { $ok = false; $err = $e->getMessage(); }
	if ( $ok === $expect_ok ) { $pass++; echo "PASS  $name\n"; }
	else { $fail++; echo "FAIL  $name" . ( $err ? " ($err)" : ' (unexpectedly verified)' ) . "\n"; }
}

$stored = null;
t( 'registration verifies', function () use ( $fx, $origins, &$stored ) {
	global $stored;
	$stored = PF_WebAuthn::verify_registration( $fx['reg']['att'], $fx['reg']['cdj'], $fx['reg']['challenge'], $fx['rp_id'], $origins );
	if ( $stored['cred_id'] !== $fx['cred_id'] ) throw new Exception( 'cred id mismatch' );
	if ( -7 !== $stored['alg'] ) throw new Exception( 'alg mismatch' );
} );
t( 'assertion verifies, count advances', function () use ( $fx, $origins ) {
	global $stored;
	$n = PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), $fx['get']['challenge'], $fx['rp_id'], $origins );
	if ( 9 !== $n ) throw new Exception( 'count wrong' );
} );
t( 'wrong challenge rejected', function () use ( $fx, $origins ) {
	global $stored;
	PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), PF_WebAuthn::b64u_encode( random_bytes( 32 ) ), $fx['rp_id'], $origins );
}, false );
t( 'wrong origin rejected', function () use ( $fx ) {
	global $stored;
	PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), $fx['get']['challenge'], $fx['rp_id'], array( 'https://evil.example' ) );
}, false );
t( 'wrong rp id rejected', function () use ( $fx, $origins ) {
	global $stored;
	PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), $fx['get']['challenge'], 'other.example', $origins );
}, false );
t( 'tampered authData rejected', function () use ( $fx, $origins ) {
	global $stored;
	$ad = PF_WebAuthn::b64u_decode( $fx['get']['ad'] );
	$ad[34] = chr( ord( $ad[34] ) ^ 0xff );
	PF_WebAuthn::verify_assertion( PF_WebAuthn::b64u_encode( $ad ), $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), $fx['get']['challenge'], $fx['rp_id'], $origins );
}, false );
t( 'tampered signature rejected', function () use ( $fx, $origins ) {
	global $stored;
	$sig = PF_WebAuthn::b64u_decode( $fx['get']['sig'] );
	$sig[10] = chr( ord( $sig[10] ) ^ 0x01 );
	PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], PF_WebAuthn::b64u_encode( $sig ), array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 5 ), $fx['get']['challenge'], $fx['rp_id'], $origins );
}, false );
t( 'sign count regression rejected', function () use ( $fx, $origins ) {
	global $stored;
	PF_WebAuthn::verify_assertion( $fx['get']['ad'], $fx['get']['cdj'], $fx['get']['sig'], array( 'pem' => $stored['pem'], 'alg' => -7, 'count' => 9 ), $fx['get']['challenge'], $fx['rp_id'], $origins );
}, false );
t( 'wrong ceremony type rejected', function () use ( $fx, $origins ) {
	global $stored;
	PF_WebAuthn::verify_registration( $fx['reg']['att'], $fx['get']['cdj'], $fx['reg']['challenge'], $fx['rp_id'], $origins );
}, false );

/* ---------------------------------------------------- software authenticator */

$rp = 'example.test'; $origin = 'https://example.test'; $so = array( $origin );
function soft_register( $cred, $o = array() ) {
	global $rp, $origin, $so;
	$ch  = PF_Soft_Authenticator::b64u( random_bytes( 32 ) );
	$reg = PF_Soft_Authenticator::register( $cred, $rp, $origin, $ch, 1, $o );
	return PF_WebAuthn::verify_registration( $reg['att'], $reg['cdj'], $ch, $rp, $so );
}
function soft_assert( &$cred, $stored, $o = array() ) {
	global $rp, $origin, $so;
	$ch = PF_Soft_Authenticator::b64u( random_bytes( 32 ) );
	$a  = PF_Soft_Authenticator::assert( $cred, $rp, $origin, $ch, 1, $o );
	return PF_WebAuthn::verify_assertion( $a['ad'], $a['cdj'], $a['sig'], $stored, $ch, $rp, $so );
}

$es = PF_Soft_Authenticator::credential( -7 );
$es_stored = null;
t( 'soft ES256 registration verifies', function () use ( $es, &$es_stored ) {
	$es_stored = soft_register( $es );
	if ( -7 !== $es_stored['alg'] ) throw new Exception( 'alg' );
} );
t( 'soft ES256 assertion verifies', function () use ( &$es, &$es_stored ) {
	soft_assert( $es, $es_stored + array( 'count' => 0 ) );
} );
$rs = PF_Soft_Authenticator::credential( -257, 2048 );
t( 'soft RS256 (2048-bit) registration and assertion verify', function () use ( &$rs ) {
	$stored = soft_register( $rs );
	if ( -257 !== $stored['alg'] ) throw new Exception( 'alg' );
	soft_assert( $rs, $stored );
} );
t( 'RSA keys under 2048 bits rejected', function () {
	soft_register( PF_Soft_Authenticator::credential( -257, 1024 ) );
}, false );

foreach ( array(
	'crossOrigin true rejected (sign-in)'  => array( 'client_extra' => array( 'crossOrigin' => true ) ),
	'topOrigin rejected (sign-in)'         => array( 'client_extra' => array( 'topOrigin' => 'https://evil.example' ) ),
	'missing user verification rejected'   => array( 'flags' => PF_Soft_Authenticator::FLAG_UP ),
	'missing user presence rejected'       => array( 'flags' => PF_Soft_Authenticator::FLAG_UV ),
	'other site\'s rpIdHash rejected'      => array( 'rp_id_hash_of' => 'evil.example' ),
	'wrong origin rejected (soft)'         => array( 'origin' => 'https://example.test.evil.example' ),
	'registration-type client data rejected for sign-in' => array( 'type' => 'webauthn.create' ),
) as $name => $o ) {
	t( $name, function () use ( &$es, &$es_stored, $o ) { soft_assert( $es, $es_stored, $o ); }, false );
}
t( 'crossOrigin true rejected (registration)', function () {
	soft_register( PF_Soft_Authenticator::credential( -7 ), array( 'client_extra' => array( 'crossOrigin' => true ) ) );
}, false );

foreach ( array(
	array( 'counter 0 after a stored 5 rejected (clone signal)', 5, 0, false ),
	array( 'counter equal to stored rejected', 5, 5, false ),
	array( 'counter that increases accepted', 5, 6, true ),
	array( 'first counted use accepted', 0, 3, true ),
	array( 'authenticators that never count (0 and 0) accepted', 0, 0, true ),
) as $c ) {
	list( $name, $old, $new, $ok ) = $c;
	t( $name, function () use ( &$es, &$es_stored, $old, $new ) {
		soft_assert( $es, array( 'pem' => $es_stored['pem'], 'alg' => -7, 'count' => $old ), array( 'count' => $new ) );
	}, $ok );
}

/* ---------------------------------------------------- malformed input fails cleanly */

$reg_raw = function ( $o = array() ) use ( $rp, $origin ) {
	$cred = PF_Soft_Authenticator::credential( -7 );
	$ch   = PF_Soft_Authenticator::b64u( random_bytes( 32 ) );
	return array( PF_Soft_Authenticator::register( $cred, $rp, $origin, $ch, 1, $o ), $ch );
};
t( 'truncated attestation rejected without warnings', function () use ( $reg_raw, $rp, $so ) {
	list( $r, $ch ) = $reg_raw();
	$att = PF_WebAuthn::b64u_decode( $r['att'] );
	for ( $cut = 1; $cut < strlen( $att ); $cut += 7 ) {
		try {
			PF_WebAuthn::verify_registration( PF_Soft_Authenticator::b64u( substr( $att, 0, $cut ) ), $r['cdj'], $ch, $rp, $so );
			throw new RuntimeException( "a $cut-byte attestation verified" );
		} catch ( InvalidArgumentException $e ) {
			// expected
		}
	}
	throw new Exception( 'all truncations rejected' );
}, false );
t( 'deeply nested CBOR rejected', function () {
	$off = 0;
	PF_WebAuthn::cbor_decode( str_repeat( "\x81", 5000 ) . "\x00", $off );
}, false );
t( 'trailing bytes after the attestation object rejected', function () use ( $reg_raw, $rp, $so ) {
	list( $r, $ch ) = $reg_raw( array( 'att_trailer' => "\x00" ) );
	PF_WebAuthn::verify_registration( $r['att'], $r['cdj'], $ch, $rp, $so );
}, false );
t( 'trailing bytes in authenticator data rejected', function () use ( $reg_raw, $rp, $so ) {
	list( $r, $ch ) = $reg_raw( array( 'auth_trailer' => "\xff\xff" ) );
	PF_WebAuthn::verify_registration( $r['att'], $r['cdj'], $ch, $rp, $so );
}, false );
t( 'duplicate CBOR map keys rejected', function () {
	$off = 0;
	PF_WebAuthn::cbor_decode( "\xa2\x01\x02\x01\x03", $off );
}, false );
t( 'credential ids shorter than 16 bytes rejected', function () use ( $rp, $origin, $so ) {
	$cred       = PF_Soft_Authenticator::credential( -7 );
	$cred['id'] = 'short';
	$ch         = PF_Soft_Authenticator::b64u( random_bytes( 32 ) );
	$r          = PF_Soft_Authenticator::register( $cred, $rp, $origin, $ch, 1 );
	PF_WebAuthn::verify_registration( $r['att'], $r['cdj'], $ch, $rp, $so );
}, false );
foreach ( array( 'plain base64 "+" rejected' => 'ab+c', 'padding rejected' => 'abc=', 'non-string rejected' => array() ) as $name => $v ) {
	t( "base64url: $name", function () use ( $v ) { PF_WebAuthn::b64u_decode( $v ); }, false );
}

echo "\n$pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
