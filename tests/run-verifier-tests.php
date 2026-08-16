<?php
// Standalone verifier test — no WordPress needed.
define( 'ABSPATH', '/' );
require __DIR__ . '/../includes/class-pf-webauthn.php';
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
echo "\n$pass passed, $fail failed\n";
exit( $fail ? 1 : 0 );
