<?php

/**
 * Encryption utility for sensitive data protection.
 *
 * Provides encryption and decryption methods for sensitive configuration data
 * using WordPress salts and OpenSSL for secure credential storage.
 *
 * @link       https://fossasia.org
 * @since      1.2.2
 * @package    Wpfa_Mailconnect
 * @subpackage Wpfa_Mailconnect/includes
 */

/**
 * Encryption utility class definition.
 *
 * @since      1.2.2
 * @package    Wpfa_Mailconnect
 * @subpackage Wpfa_Mailconnect/includes
 * @author     FOSSASIA <info@fossasia.org>
 */
class Wpfa_Mailconnect_Encryption {

	/**
	 * Encryption method to use.
	 *
	 * @since 1.2.2
	 */
	const CIPHER_METHOD = 'AES-256-CBC';

	/**
	 * Prefix to identify encrypted values.
	 *
	 * @since 1.2.2
	 */
	const ENCRYPTED_PREFIX = 'wpfa_enc_';

	/**
	 * Encrypts a string value.
	 *
	 * Uses OpenSSL with AES-256-CBC encryption and WordPress salts for the key.
	 *
	 * @since  1.2.2
	 * @param  string $value The plain text value to encrypt.
	 * @return string        The encrypted value with prefix, or original value if encryption fails.
	 */
	public static function encrypt( $value ) {
		// Return empty if value is empty
		if ( empty( $value ) ) {
			return $value;
		}

		// Don't re-encrypt already encrypted values
		if ( self::is_encrypted( $value ) ) {
			return $value;
		}

		// Check if OpenSSL is available
		if ( ! function_exists( 'openssl_encrypt' ) ) {
			error_log( 'WPFA MailConnect: OpenSSL not available, storing value without encryption.' );
			return $value;
		}

		try {
			$key = self::get_encryption_key();
			$iv  = openssl_random_pseudo_bytes( openssl_cipher_iv_length( self::CIPHER_METHOD ) );

			$encrypted = openssl_encrypt(
				$value,
				self::CIPHER_METHOD,
				$key,
				0,
				$iv
			);

			if ( false === $encrypted ) {
				error_log( 'WPFA MailConnect: Encryption failed.' );
				return $value;
			}

			// Combine IV and encrypted data, then base64 encode
			$result = base64_encode( $iv . $encrypted );

			// Add prefix to identify encrypted values
			return self::ENCRYPTED_PREFIX . $result;

		} catch ( Exception $e ) {
			error_log( 'WPFA MailConnect Encryption Error: ' . $e->getMessage() );
			return $value;
		}
	}

	/**
	 * Decrypts an encrypted string value.
	 *
	 * @since  1.2.2
	 * @param  string $value The encrypted value (with prefix).
	 * @return string        The decrypted plain text value, or original if not encrypted.
	 */
	public static function decrypt( $value ) {
		// Return empty if value is empty
		if ( empty( $value ) ) {
			return $value;
		}

		// If not encrypted, return as-is (backwards compatibility)
		if ( ! self::is_encrypted( $value ) ) {
			return $value;
		}

		// Store the original encrypted value to return on failure, preventing silent data loss.
		$original_value = $value;

		// Check if OpenSSL is available
		if ( ! function_exists( 'openssl_decrypt' ) ) {
			error_log( 'WPFA MailConnect: OpenSSL not available for decryption. Returning original value.' );
			return $original_value; // Return original stored value
		}

		try {
			// Remove prefix
			$payload = substr( $value, strlen( self::ENCRYPTED_PREFIX ) );

			// Decode from base64
			$decoded = base64_decode( $payload, true );

			if ( false === $decoded ) {
				error_log( 'WPFA MailConnect: Base64 decode failed. Returning original value.' );
				return $original_value;
			}

			$key       = self::get_encryption_key();
			$iv_length = openssl_cipher_iv_length( self::CIPHER_METHOD );

			// Extract IV and encrypted data
			$iv        = substr( $decoded, 0, $iv_length );
			$encrypted = substr( $decoded, $iv_length );

			$decrypted = openssl_decrypt(
				$encrypted,
				self::CIPHER_METHOD,
				$key,
				0,
				$iv
			);

			if ( false === $decrypted ) {
				error_log( 'WPFA MailConnect: Decryption failed. Returning original value.' );
				return $original_value;
			}

			return $decrypted;

		} catch ( Exception $e ) {
			error_log( 'WPFA MailConnect Decryption Error: ' . $e->getMessage() . '. Returning original value.' );
			return $original_value;
		}
	}

	/**
	 * Checks if a value is encrypted.
	 *
	 * @since  1.2.2
	 * @param  string $value The value to check.
	 * @return bool          True if encrypted, false otherwise.
	 */
	public static function is_encrypted( $value ) {
		return is_string( $value ) && strpos( $value, self::ENCRYPTED_PREFIX ) === 0;
	}

	/**
	 * Generates an encryption key based on WordPress salts.
	 *
	 * Uses WordPress AUTH_KEY and SECURE_AUTH_KEY salts to create a unique,
	 * site-specific encryption key.
	 *
	 * @since  1.2.2
	 * @return string The encryption key.
	 */
	private static function get_encryption_key() {
		// Use WordPress salts to create a unique key per site
		$key = AUTH_KEY . SECURE_AUTH_KEY;

		// Hash to ensure consistent key length for AES-256 (32 bytes)
		return hash( 'sha256', $key, true );
	}
}