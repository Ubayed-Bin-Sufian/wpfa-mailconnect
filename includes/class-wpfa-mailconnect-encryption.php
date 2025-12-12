<?php

/**
 * Encryption utility for sensitive data protection.
 *
 * Provides encryption and decryption methods for sensitive configuration data
 * using WordPress salts and OpenSSL for secure credential storage. The encryption
 * uses AES-256-GCM for authenticated encryption (confidentiality and integrity).
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
	 * Encryption method to use (AES-256-GCM for authenticated encryption).
	 *
	 * @since 1.2.3 (Changed from AES-256-CBC)
	 */
	const CIPHER_METHOD = 'AES-256-GCM';

	/**
	 * Length of the authentication tag in bytes (128 bits) for AES-GCM.
	 *
	 * @since 1.2.3
	 */
	const TAG_LENGTH = 16;

	/**
	 * Prefix to identify encrypted values.
	 *
	 * @since 1.2.2
	 */
	const ENCRYPTED_PREFIX = 'wpfa_enc_';

	/**
	 * Encrypts a string value using AES-256-GCM.
	 *
	 * Uses OpenSSL with AES-256-GCM authenticated encryption and WordPress salts for the key.
	 * The output is IV + Authentication Tag + Ciphertext, Base64 encoded.
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
			
			// IV length for AES-256-GCM is typically 12 bytes (96 bits) for security
			$iv_length = openssl_cipher_iv_length( self::CIPHER_METHOD );
			$iv	 = openssl_random_pseudo_bytes( $iv_length );
			$tag = ''; // Required variable for the GCM authentication tag

			$encrypted = openssl_encrypt(
				$value,
				self::CIPHER_METHOD,
				$key,
				OPENSSL_RAW_DATA, // Use raw data mode for GCM
				$iv,
				$tag, // Output parameter for the authentication tag
				'', // Additional authenticated data (none needed here)
				self::TAG_LENGTH // Length of the authentication tag (16 bytes)
			);

			if ( false === $encrypted ) {
				error_log( 'WPFA MailConnect: Encryption failed.' );
				return $value;
			}

			// Combine IV, Tag, and encrypted data, then base64 encode
			// Order: IV | Tag | Ciphertext
			$result = base64_encode( $iv . $tag . $encrypted );

			// Add prefix to identify encrypted values
			return self::ENCRYPTED_PREFIX . $result;

		} catch ( Exception $e ) {
			error_log( 'WPFA MailConnect Encryption Error: ' . $e->getMessage() );
			return $value;
		}
	}

	/**
	 * Decrypts an authenticated encrypted string value using AES-256-GCM.
	 *
	 * @since  1.2.2
	 * @param  string $value The encrypted value (with prefix).
	 * @return string        The decrypted plain text value, or original if not encrypted/decryption fails.
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
			return $original_value;
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
			$tag_length = self::TAG_LENGTH;

			// Check if the decoded payload is long enough (IV + Tag + at least one block of data)
			if ( strlen( $decoded ) < $iv_length + $tag_length ) {
				error_log( 'WPFA MailConnect: Decoded payload is too short. Returning original value.' );
				return $original_value;
			}

			// Extract IV, Tag, and encrypted data
			$iv			 = substr( $decoded, 0, $iv_length );
			$tag		 = substr( $decoded, $iv_length, $tag_length );
			$encrypted = substr( $decoded, $iv_length + $tag_length );

			$decrypted = openssl_decrypt(
				$encrypted,
				self::CIPHER_METHOD,
				$key,
				OPENSSL_RAW_DATA, // Use raw data mode for GCM
				$iv,
				$tag // Input parameter for the authentication tag
			);

			if ( false === $decrypted ) {
				// Decryption fails if the tag does not match the ciphertext (tampering detected)
				error_log( 'WPFA MailConnect: Decryption or authentication failed (possible tampering). Returning original value.' );
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