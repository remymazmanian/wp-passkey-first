<?php
/**
 * Plain-PHP WebAuthn verifier for Passkey First.
 *
 * Copyright (C) 2026 Remy Mazmanian
 * GPL-2.0-or-later. See LICENSE.
 *
 * Scope is deliberate: attestation format "none" (we keep the public key,
 * we do not judge the authenticator), definite-length CBOR only, ES256 and
 * RS256 (2048-bit or larger) only. Signature verification runs on OpenSSL.
 * Every parse failure throws; callers treat any exception as a hard
 * verification failure.
 */

defined( 'ABSPATH' ) || exit;

final class PF_WebAuthn {

	/** Deepest CBOR nesting accepted. A COSE key in an attestation object needs 3. */
	const CBOR_MAX_DEPTH = 8;

	/** Smallest RSA modulus accepted, in bytes (2048 bits). */
	const RSA_MIN_BYTES = 256;

	/* ------------------------------------------------ base64url */

	public static function b64u_decode( $s ) {
		if ( ! is_string( $s ) || ! preg_match( '/^[A-Za-z0-9_-]*$/', $s ) ) {
			throw new InvalidArgumentException( 'bad base64url' );
		}
		$s = strtr( $s, '-_', '+/' );
		$d = base64_decode( $s . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true );
		if ( false === $d ) {
			throw new InvalidArgumentException( 'bad base64url' );
		}
		return $d;
	}

	public static function b64u_encode( $b ) {
		return rtrim( strtr( base64_encode( $b ), '+/', '-_' ), '=' );
	}

	/* ------------------------------------------------ CBOR (strict subset) */

	/** Returns $n bytes at $off and advances $off, or throws if the input is shorter. */
	private static function take( $bin, &$off, $n ) {
		if ( $n < 0 || $off + $n > strlen( $bin ) ) {
			throw new InvalidArgumentException( 'cbor: truncated' );
		}
		$out  = substr( $bin, $off, $n );
		$off += $n;
		return $out;
	}

	/**
	 * Decodes one CBOR item starting at $off; advances $off.
	 * Definite lengths only. Majors: uint, negint, bstr, tstr, array, map.
	 * Nesting is capped at CBOR_MAX_DEPTH so hostile input can't exhaust the stack.
	 */
	public static function cbor_decode( $bin, &$off, $depth = 0 ) {
		if ( $depth > self::CBOR_MAX_DEPTH ) {
			throw new InvalidArgumentException( 'cbor: nested too deeply' );
		}
		$ib    = ord( self::take( $bin, $off, 1 ) );
		$major = $ib >> 5;
		$info  = $ib & 0x1f;

		if ( $info < 24 ) {
			$len = $info;
		} elseif ( 24 === $info ) {
			$len = ord( self::take( $bin, $off, 1 ) );
		} elseif ( 25 === $info ) {
			$len = unpack( 'n', self::take( $bin, $off, 2 ) )[1];
		} elseif ( 26 === $info ) {
			$len = unpack( 'N', self::take( $bin, $off, 4 ) )[1];
		} elseif ( 27 === $info ) {
			$both = unpack( 'Nhi/Nlo', self::take( $bin, $off, 8 ) );
			if ( $both['hi'] ) {
				throw new InvalidArgumentException( 'cbor: length too large' );
			}
			$len = $both['lo'];
		} else {
			throw new InvalidArgumentException( 'cbor: indefinite length unsupported' );
		}

		switch ( $major ) {
			case 0:
				return $len;
			case 1:
				return -1 - $len;
			case 2:
			case 3:
				return self::take( $bin, $off, $len );
			case 4:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$out[] = self::cbor_decode( $bin, $off, $depth + 1 );
				}
				return $out;
			case 5:
				$out = array();
				for ( $i = 0; $i < $len; $i++ ) {
					$k = self::cbor_decode( $bin, $off, $depth + 1 );
					$v = self::cbor_decode( $bin, $off, $depth + 1 );
					if ( ! is_int( $k ) && ! is_string( $k ) ) {
						throw new InvalidArgumentException( 'cbor: bad map key' );
					}
					if ( array_key_exists( $k, $out ) ) {
						throw new InvalidArgumentException( 'cbor: duplicate map key' );
					}
					$out[ $k ] = $v;
				}
				return $out;
			default:
				throw new InvalidArgumentException( 'cbor: unsupported major ' . $major );
		}
	}

	/* ------------------------------------------------ COSE → PEM */

	private static function der_len( $bin ) {
		$n = strlen( $bin );
		if ( $n < 0x80 ) {
			return chr( $n ) . $bin;
		}
		$l = ltrim( pack( 'N', $n ), "\0" );
		return chr( 0x80 | strlen( $l ) ) . $l . $bin;
	}

	private static function der_seq( $bin ) {
		return "\x30" . self::der_len( $bin );
	}

	private static function der_uint( $bin ) {
		$bin = ltrim( $bin, "\0" );
		if ( '' === $bin || ord( $bin[0] ) > 0x7f ) {
			$bin = "\0" . $bin;
		}
		return "\x02" . self::der_len( $bin );
	}

	private static function der_bits( $bin ) {
		return "\x03" . self::der_len( "\0" . $bin );
	}

	/**
	 * COSE key map → array( pem, alg ). EC2 P-256 and RSA only.
	 */
	public static function cose_to_pem( $key ) {
		if ( ! is_array( $key ) || ! isset( $key[1], $key[3] ) ) {
			throw new InvalidArgumentException( 'cose: malformed key' );
		}
		$kty = $key[1];
		$alg = $key[3];

		if ( 2 === $kty && -7 === $alg ) { // EC2 / ES256
			if ( 1 !== ( $key[-1] ?? 0 ) || 32 !== strlen( $key[-2] ?? '' ) || 32 !== strlen( $key[-3] ?? '' ) ) {
				throw new InvalidArgumentException( 'cose: bad P-256 key' );
			}
			$point = "\x04" . $key[-2] . $key[-3];
			$algid = self::der_seq(
				"\x06\x07\x2a\x86\x48\xce\x3d\x02\x01" .      // id-ecPublicKey
				"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"    // prime256v1
			);
			$spki  = self::der_seq( $algid . self::der_bits( $point ) );
		} elseif ( 3 === $kty && -257 === $alg ) { // RSA / RS256
			if ( ! is_string( $key[-1] ?? null ) || ! is_string( $key[-2] ?? null ) || '' === ltrim( $key[-2], "\0" ) ) {
				throw new InvalidArgumentException( 'cose: bad RSA key' );
			}
			if ( strlen( ltrim( $key[-1], "\0" ) ) < self::RSA_MIN_BYTES ) {
				throw new InvalidArgumentException( 'cose: RSA keys must be at least 2048 bits' );
			}
			$rsa   = self::der_seq( self::der_uint( $key[-1] ) . self::der_uint( $key[-2] ) );
			$algid = self::der_seq( "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00" ); // rsaEncryption, NULL
			$spki  = self::der_seq( $algid . self::der_bits( $rsa ) );
		} else {
			throw new InvalidArgumentException( 'cose: unsupported kty/alg ' . $kty . '/' . $alg );
		}

		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		if ( false === openssl_pkey_get_public( $pem ) ) {
			throw new InvalidArgumentException( 'cose: OpenSSL rejected the converted key' );
		}
		return array( 'pem' => $pem, 'alg' => $alg );
	}

	/* ------------------------------------------------ authenticator data */

	public static function parse_auth_data( $ad, $need_attested = false ) {
		if ( strlen( $ad ) < 37 ) {
			throw new InvalidArgumentException( 'authData: too short' );
		}
		$out = array(
			'rpIdHash' => substr( $ad, 0, 32 ),
			'flags'    => ord( $ad[32] ),
			'count'    => unpack( 'N', substr( $ad, 33, 4 ) )[1],
			'cred_id'  => null,
			'cose'     => null,
		);
		if ( $need_attested ) {
			if ( ! ( $out['flags'] & 0x40 ) ) {
				throw new InvalidArgumentException( 'authData: attested credential data missing' );
			}
			if ( strlen( $ad ) < 55 ) {
				throw new InvalidArgumentException( 'authData: truncated attested data' );
			}
			$id_len = unpack( 'n', substr( $ad, 53, 2 ) )[1];
			if ( strlen( $ad ) < 55 + $id_len ) {
				throw new InvalidArgumentException( 'authData: truncated credential id' );
			}
			if ( $id_len < 16 || $id_len > 1023 ) {
				throw new InvalidArgumentException( 'authData: credential id length out of range' );
			}
			$out['cred_id'] = substr( $ad, 55, $id_len );
			$off            = 55 + $id_len;
			$out['cose']    = self::cbor_decode( $ad, $off );
			// Extension data may follow only when the ED flag says so.
			if ( ! ( $out['flags'] & 0x80 ) && strlen( $ad ) !== $off ) {
				throw new InvalidArgumentException( 'authData: unexpected trailing bytes' );
			}
		}
		return $out;
	}

	/* ------------------------------------------------ shared checks */

	private static function check_client_data( $cdj, $type, $challenge_b64u, $origins ) {
		$cd = json_decode( $cdj, true );
		if ( ! is_array( $cd ) ) {
			throw new InvalidArgumentException( 'clientData: not JSON' );
		}
		if ( ( $cd['type'] ?? '' ) !== $type ) {
			throw new InvalidArgumentException( 'clientData: wrong type' );
		}
		if ( ! isset( $cd['challenge'] ) || ! hash_equals( $challenge_b64u, (string) $cd['challenge'] ) ) {
			throw new InvalidArgumentException( 'clientData: challenge mismatch' );
		}
		if ( ! in_array( $cd['origin'] ?? '', $origins, true ) ) {
			throw new InvalidArgumentException( 'clientData: origin not allowed' );
		}
		// Passkeys are only used on this site's own pages, never inside another site's frame.
		if ( true === ( $cd['crossOrigin'] ?? false ) || isset( $cd['topOrigin'] ) ) {
			throw new InvalidArgumentException( 'clientData: cross-origin use not allowed' );
		}
	}

	private static function check_binding( $parsed, $rp_id, $require_uv ) {
		if ( ! hash_equals( hash( 'sha256', $rp_id, true ), $parsed['rpIdHash'] ) ) {
			throw new InvalidArgumentException( 'authData: rpIdHash mismatch' );
		}
		if ( ! ( $parsed['flags'] & 0x01 ) ) {
			throw new InvalidArgumentException( 'authData: user presence not set' );
		}
		if ( $require_uv && ! ( $parsed['flags'] & 0x04 ) ) {
			throw new InvalidArgumentException( 'authData: user verification required but not set' );
		}
	}

	/* ------------------------------------------------ ceremonies */

	/**
	 * Registration: attestationObject + clientDataJSON (both base64url).
	 * Returns array( cred_id_b64u, pem, alg, count ).
	 */
	public static function verify_registration( $att_b64u, $cdj_b64u, $challenge_b64u, $rp_id, $origins ) {
		$cdj = self::b64u_decode( $cdj_b64u );
		self::check_client_data( $cdj, 'webauthn.create', $challenge_b64u, $origins );

		$off = 0;
		$raw = self::b64u_decode( $att_b64u );
		$att = self::cbor_decode( $raw, $off );
		if ( strlen( $raw ) !== $off ) {
			throw new InvalidArgumentException( 'attestation: unexpected trailing bytes' );
		}
		if ( ! is_array( $att ) || empty( $att['authData'] ) || ! is_string( $att['authData'] ) ) {
			throw new InvalidArgumentException( 'attestation: malformed object' );
		}
		$parsed = self::parse_auth_data( $att['authData'], true );
		self::check_binding( $parsed, $rp_id, true );

		$key = self::cose_to_pem( $parsed['cose'] );
		return array(
			'cred_id' => self::b64u_encode( $parsed['cred_id'] ),
			'pem'     => $key['pem'],
			'alg'     => $key['alg'],
			'count'   => $parsed['count'],
		);
	}

	/**
	 * Assertion: raw fields base64url, stored credential array with pem/alg/count.
	 * Returns the new sign count. Throws on any failure.
	 */
	public static function verify_assertion( $ad_b64u, $cdj_b64u, $sig_b64u, $stored, $challenge_b64u, $rp_id, $origins ) {
		$cdj = self::b64u_decode( $cdj_b64u );
		self::check_client_data( $cdj, 'webauthn.get', $challenge_b64u, $origins );

		$ad     = self::b64u_decode( $ad_b64u );
		$parsed = self::parse_auth_data( $ad, false );
		self::check_binding( $parsed, $rp_id, true );

		$base = $ad . hash( 'sha256', $cdj, true );
		$ok   = openssl_verify( $base, self::b64u_decode( $sig_b64u ), $stored['pem'], OPENSSL_ALGO_SHA256 );
		if ( 1 !== $ok ) {
			throw new InvalidArgumentException( 'signature: verification failed' );
		}

		// WebAuthn L2 7.2 step 21: once either counter is non-zero it must strictly
		// increase. Authenticators that never count (both zero) are accepted.
		$new = $parsed['count'];
		$old = (int) $stored['count'];
		if ( ( $new > 0 || $old > 0 ) && $new <= $old ) {
			throw new InvalidArgumentException( 'signature: sign count did not increase (possible cloned credential)' );
		}
		return $new;
	}
}
