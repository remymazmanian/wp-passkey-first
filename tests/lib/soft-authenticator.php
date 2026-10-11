<?php
/**
 * A software WebAuthn authenticator for tests: real ES256/RS256 keys, real
 * signatures, and knobs to produce the malformed or hostile responses a
 * verifier has to reject.
 *
 * Copyright (C) 2026 Remy Mazmanian
 * GPL-2.0-or-later. See LICENSE.
 */

final class PF_Test_Bytes {
	public $bin;
	public function __construct( $bin ) {
		$this->bin = $bin;
	}
}

final class PF_Soft_Authenticator {

	const FLAG_UP = 0x01;
	const FLAG_UV = 0x04;
	const FLAG_AT = 0x40;

	public static function b64u( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	/** Minimal CBOR encoder: ints, PF_Test_Bytes (bstr), strings (tstr), lists, maps. */
	public static function cbor( $v ) {
		if ( $v instanceof PF_Test_Bytes ) {
			return self::head( 2, strlen( $v->bin ) ) . $v->bin;
		}
		if ( is_int( $v ) ) {
			return $v >= 0 ? self::head( 0, $v ) : self::head( 1, -1 - $v );
		}
		if ( is_string( $v ) ) {
			return self::head( 3, strlen( $v ) ) . $v;
		}
		if ( is_array( $v ) ) {
			if ( array_keys( $v ) === range( 0, count( $v ) - 1 ) ) {
				return self::head( 4, count( $v ) ) . implode( '', array_map( array( __CLASS__, 'cbor' ), $v ) );
			}
			$out = self::head( 5, count( $v ) );
			foreach ( $v as $k => $item ) {
				$out .= self::cbor( $k ) . self::cbor( $item );
			}
			return $out;
		}
		throw new InvalidArgumentException( 'cbor: unsupported test value' );
	}

	public static function head( $major, $len ) {
		if ( $len < 24 ) {
			return chr( ( $major << 5 ) | $len );
		}
		if ( $len < 0x100 ) {
			return chr( ( $major << 5 ) | 24 ) . chr( $len );
		}
		if ( $len < 0x10000 ) {
			return chr( ( $major << 5 ) | 25 ) . pack( 'n', $len );
		}
		return chr( ( $major << 5 ) | 26 ) . pack( 'N', $len );
	}

	/** A new credential: array( id, private key, COSE public key ). */
	public static function credential( $alg = -7, $rsa_bits = 2048 ) {
		if ( -7 === $alg ) {
			$key = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1' ) );
			$d   = openssl_pkey_get_details( $key )['ec'];
			$cose = array( 1 => 2, 3 => -7, -1 => 1, -2 => new PF_Test_Bytes( str_pad( $d['x'], 32, "\0", STR_PAD_LEFT ) ), -3 => new PF_Test_Bytes( str_pad( $d['y'], 32, "\0", STR_PAD_LEFT ) ) );
		} else {
			$key  = openssl_pkey_new( array( 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $rsa_bits ) );
			$d    = openssl_pkey_get_details( $key )['rsa'];
			$cose = array( 1 => 3, 3 => -257, -1 => new PF_Test_Bytes( $d['n'] ), -2 => new PF_Test_Bytes( $d['e'] ) );
		}
		return array( 'id' => random_bytes( 32 ), 'key' => $key, 'cose' => $cose, 'count' => 0 );
	}

	public static function client_data( $type, $challenge, $origin, $extra = array() ) {
		return json_encode( array_merge( array( 'type' => $type, 'challenge' => $challenge, 'origin' => $origin, 'crossOrigin' => false ), $extra ), JSON_UNESCAPED_SLASHES );
	}

	/**
	 * Registration response. $o: flags, origin override, client_data extras,
	 * attestation map extras, raw COSE override, trailing bytes.
	 */
	public static function register( $cred, $rp_id, $origin, $challenge, $user_id, $o = array() ) {
		$flags = $o['flags'] ?? ( self::FLAG_UP | self::FLAG_UV | self::FLAG_AT );
		$cose  = array_key_exists( 'cose_raw', $o ) ? $o['cose_raw'] : self::cbor( $cred['cose'] );
		$auth  = hash( 'sha256', $o['rp_id_hash_of'] ?? $rp_id, true ) . chr( $flags ) . pack( 'N', $o['count'] ?? 0 )
			. str_repeat( "\0", 16 ) . pack( 'n', strlen( $cred['id'] ) ) . $cred['id'] . $cose . ( $o['auth_trailer'] ?? '' );
		$att   = self::cbor( array( 'fmt' => 'none', 'attStmt' => array(), 'authData' => new PF_Test_Bytes( $auth ) ) ) . ( $o['att_trailer'] ?? '' );
		$cdj   = self::client_data( $o['type'] ?? 'webauthn.create', $challenge, $o['origin'] ?? $origin, $o['client_extra'] ?? array() );
		return array( 'att' => self::b64u( $att ), 'cdj' => self::b64u( $cdj ), 'cred_id' => self::b64u( $cred['id'] ), 'uh' => self::b64u( pack( 'N', $user_id ) ) );
	}

	/** Assertion response for $cred, signed with its private key. */
	public static function assert( &$cred, $rp_id, $origin, $challenge, $user_id, $o = array() ) {
		$flags = $o['flags'] ?? ( self::FLAG_UP | self::FLAG_UV );
		$count = array_key_exists( 'count', $o ) ? $o['count'] : ++$cred['count'];
		$auth  = hash( 'sha256', $o['rp_id_hash_of'] ?? $rp_id, true ) . chr( $flags ) . pack( 'N', $count );
		$cdj   = self::client_data( $o['type'] ?? 'webauthn.get', $challenge, $o['origin'] ?? $origin, $o['client_extra'] ?? array() );
		openssl_sign( $auth . hash( 'sha256', $cdj, true ), $sig, $cred['key'], OPENSSL_ALGO_SHA256 );
		return array(
			'id'  => self::b64u( $cred['id'] ),
			'ad'  => self::b64u( $auth ),
			'cdj' => self::b64u( $cdj ),
			'sig' => self::b64u( $sig ),
			'uh'  => self::b64u( pack( 'N', $user_id ) ),
		);
	}
}
