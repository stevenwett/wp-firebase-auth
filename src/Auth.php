<?php
/**
 * Auth is a controller class for interfacing with Kreait and Firebase
 *
 * @package WPFirebaseAuth
 * @author  Steven Wett <stevenwett@gmail.com>
 * @version 0.0.1
 */

namespace WPFirebaseAuth;

if (! defined('ABSPATH')) {
	die();
}

// TODO: Set ROOTPATH.

use \Kreait\Firebase\Factory;
use \Kreait\Firebase\ServiceAccount;
use \Kreait\Firebase\Request;
use \Firebase\Auth\Token\Exception\InvalidToken;
use \Kreait\Firebase\Exception\InvalidArgumentException;
use \Kreait\Firebase\Auth\CreateSessionCookie\FailedToCreateSessionCookie;
use \Lcobucci\JWT\Configuration;
use \Lcobucci\JWT\UnencryptedToken;
use \Lcobucci\JWT\Signer\Key\InMemory;

/**
 * Auth Controller
 */
class Auth {
	/**
	 * Path to Gogle service account json config
	 *
	 * @var string $google_service_account_config_path Path.
	 */
	private $google_service_account_config_path;

	/**
	 * Firebase project ID
	 *
	 * @var string $project_id Firebase project ID.
	 */
	private $project_id = null;

	/**
	 * Session time
	 *
	 * @var int $session_timestamp Session time in seconds.
	 */
	private $session_timestamp = 86400 * 14; // Two weeks.

	/**
	 * Current user record.
	 *
	 * @var mixed|object $user Current User Record.
	 */
	private $user_record = false;

	/**
	 * Firebase unique ID for the current user
	 * Created by Firebase
	 *
	 * @var string $firebase_uid Firebase ID for the user.
	 */
	public $firebase_uid = false;

	/**
	 * User authentication status
	 *
	 * @var bool $is_authorized Is signed in.
	 */
	public $is_authorized = false;

	/**
	 * Constructor
	 *
	 * @param bool $start_auth_session Start the auth session.
	 * @param bool $init               Whether this is the initialization instance.
	 */
	public function __construct( $start_auth_session = false, $init = false ) {
		require_once '../includes/firebase-auth/class-strictvalidatforfirebase.php';
		require_once '../includes/firebase-auth/class-authtime.php';

		if ( $init ) {
			add_action( 'rest_api_init', array( $this, 'register_endpoints' ) );
		}

		// Setting up the Kreait Firebase factory.
		$factory                                  = new \Kreait\Firebase\Factory();
		$this->google_service_account_config_path = ROOTPATH . '/google-service-account.json';

		$service_account = $factory->withServiceAccount( $this->google_service_account_config_path );
		$this->auth      = $service_account->createAuth();

		// Start the session.
		if ( $start_session ) {
			session_set_cookie_params( $this->session_timestamp );
			session_start();
		}

		// Check if there's a session set.
		if ( ! isset( $_SESSION['user_auth'] ) ) {
			return false;
		}
		$session_token = $this->parse_session_cookie( $_SESSION['user_auth'] );

		// If the session is set and there's a sub claim, that will contain the firebase_uid.
		if ( false !== $session_token && null !== $session_token->claims()->get( 'sub' ) ) {
			$this->firebase_uid = $session_token->claims()->get( 'sub' );
		}

		// Now the user is authenticated.
		$this->is_authorized = true;
	}

	/**
	 * Registering endpoints using the WordPress REST API
	 */
	public function register_auth_endpoints() {
	}

	/**
	 * Endpoint permissions for authenticated users
	 */
	public function endpoint_permissions_authenticated_users() {
		return $this->is_authorized;
	}

	/**
	 * Endpoint permissions for the public.
	 */
	public function endpoint_permissions_public() {
		return true;
	}

	/**
	 * Verify a hash
	 *
	 * @param string $string A string to verify the hash against.
	 * @param string $hash Hash.
	 */
	public static function verify_hash( $string, $hash ) {
		$test_hash = sha1( (string) $string . wp_salt() );

		if ( strtolower( $hash ) === $test_hash ) {
			return true;
		}
		return false;
	}

	/**
	 * Get a hash;
	 *
	 * @param string $string A string.
	 */
	public static function get_hash( $string ) {
		return sha1( (string) $string . wp_salt() );
	}

	/**
	 * Function for creating a JWT and encoding it
	 *
	 * @param array $data    An array of data.
	 * @param int   $expires When it expires in seconds.
	 *
	 * @throws \Exception $e Errors.
	 */
	public function create_token( $data, $expires = 3600 ) {
		try {
			$private_key = \Lcobucci\JWT\Signer\Key\InMemory::file( ROOTPATH . '/jwtRS256.key' );
			$signer      = new \Lcobucci\JWT\Signer\Rsa\Sha256();
			$jwt_config  = \Lcobucci\JWT\Configuration::forSymmetricSigner(
				$signer,
				$private_key
			);

			if ( ! $jwt_config instanceof \Lcobucci\JWT\Configuration ) {
				throw new \Exception( 'No JWT configuration', 107 );
			}

			$now     = new \DateTimeImmutable();
			$builder = $jwt_config->builder()
				// Header.
				->withHeader( 'alg', 'RS256' )
				->withHeader( 'typ', 'JWT' )
				// Payload.
				// Registered claims.
				->issuedBy( WP_HOME ) // iss claim.
				->issuedAt( $now ); // iat claim.

			// Add an expires claim.
			if ( false !== $expires ) {
				$builder->expiresAt( $now->modify( $expires . ' sec' ) ); // exp claim.
			}

			// Adding private claims.
			if ( ! empty( $data ) ) {
				foreach ( $data as $claim => $value ) {
					$builder->withClaim( $claim, $value );
				}
			}

			// Issuing token.
			$token = $builder->getToken( $jwt_config->signer(), $jwt_config->signingKey() );

			// Return the token string.
			return $token->toString();

		} catch ( \Exception $e ) {
			// TODO: Log error.
		}
		return false;
	}

	/**
	 * Function for decoding a JWT string and getting the payload
	 *
	 * @param string $token_string Token string.
	 *
	 * @throws \Exception $e Errors.
	 * @throws \RuntimeException $e Runtime errors.
	 */
	public function parse_token( $token_string ) {
		try {
			$private_key = \Lcobucci\JWT\Signer\Key\InMemory::file( ROOTPATH . '/jwtRS256.key' );
			$public_key  = \Lcobucci\JWT\Signer\Key\InMemory::file( ROOTPATH . '/jwtRS256.key.pub' );
			$signer      = new \Lcobucci\JWT\Signer\Rsa\Sha256();
			$jwt_config  = \Lcobucci\JWT\Configuration::forSymmetricSigner(
				$signer,
				$private_key
			);

			if ( ! $jwt_config instanceof \Lcobucci\JWT\Configuration ) {
				throw new \Exception( 'No JWT configuration.', 107 );
			}

			$token = $jwt_config->parser()->parse( $token_string );

			if ( ! $token instanceof \Lcobucci\JWT\UnencryptedToken ) {
				throw new \Exception( 'JWT is not a plain token.', 108 );
			}

			$now = new \DateTimeImmutable();
			if ( $token->claims()->has( 'exp' ) && $token->isExpired( $now ) ) {
				$response_code    = 408;
				$response_message = 'Request has expired.';
				throw new \Exception( 'Token has expired.', 408 );
			}

			$constraint_iss = new \Lcobucci\JWT\Validation\Constraint\IssuedBy( WP_HOME );
			$constraint_alg = new \Lcobucci\JWT\Validation\Constraint\SignedWith(
				$signer,
				$public_key
			);

			$validate = $jwt_config->validator()->validate(
				$token,
				$constraint_iss,
				$constraint_alg
			);

			if ( ! $validate ) {
				throw new \RuntimeException( 'JWT constraints did not pass.', 113 );
			}

			if ( empty( $token ) ) {
				throw new \Exception( 'Parsed token empty.', 400 );
			}

			return $token;
		} catch ( \Lcobucci\JWT\Validation\ConstraintViolation $e ) {
			// Constraint violation.
			// TODO: Log error.
		} catch ( \Exception $e ) {
			// TODO: Log error.
		}

		return false;
	}

	/**
	 * Get Firebase UID from session cookie
	 *
	 * @param string $session_cookie Session cookie.
	 *
	 * @throws \Exception $e Errors.
	 */
	private function parse_session_cookie( $session_cookie ) {
		$session_token = false;

		try {
			$config_encoded_json_string = file_get_contents( $this->google_service_account_config_path );

			if ( false === $config_encoded_json_string ) {
				throw new \Exception( 'Could not read Google service account configuration file.', 103 );
			}

			$config_json_string = json_decode( $config_encoded_json_string );

			if ( null === $config_json_string ) {
				throw new \Exception( 'Google service account JSON could not be decoded into a JSON object.', 104 );
			}

			$private_key = '';

			if ( ! empty( $config_json_string->private_key ) ) {
				$private_key = str_replace( "\n", '', $config_json_string->private_key );
				$private_key = str_replace( '-----BEGIN PRIVATE KEY-----', '', $private_key );
				$private_key = str_replace( '-----END PRIVATE KEY-----', '', $private_key );
			} else {
				throw new \Exception( 'Google service account does not have a private key.', 106 );
			}

			$signer = new \Lcobucci\JWT\Signer\Rsa\Sha256();

			$jwt_config = \Lcobucci\JWT\Configuration::forSymmetricSigner(
				$signer,
				\Lcobucci\JWT\Signer\Key\InMemory::base64Encoded( $private_key )
			);

			$session_token = $jwt_config->parser()->parse( $session_cookie );

			if ( ! $session_token instanceof \Lcobucci\JWT\UnencryptedToken ) {
				throw new \Exception( 'JWT is not an UnecryptedToken.', 108 );
			}
		} catch ( \Exception $e ) {
			// TODO: Log error.
		}

		return $session_token;
	}

	/**
	 * Create a Firebase user and return the Firebase Unique ID
	 *
	 * @param string $email Email address for the new user.
	 */
	private function create_firebase_user( $email = false ) {
		if ( empty( $email ) ) {
			return false;
		}

		// Create a new firebase user with a random password.
		$new_user = $this->auth->createUserWithEmailAndPassword( $email, utf8_encode( random_bytes( 50 ) ) );

		if ( ! empty( $new_user ) ) {
			return $new_user;
		}
		return false;
	}

	/**
	 * Delete a Firebase user
	 *
	 * @param string $uid Firebase Unique ID.
	 */
	private function delete_firebase_user( $uid ) {
		if ( empty( $uid ) ) {
			return false;
		}

		// Delete user from the $uid.
		$this->auth->deleteUser( $uid );
		return true;
	}

	/**
	 * Update a user password in Firebase
	 *
	 * @param string $firebase_uid Firebase unique ID.
	 * @param string $new_password New user password.
	 *
	 * @throws \Exception $e Errors.
	 */
	private function reset_password( $firebase_uid = null, $new_password = '' ) {
		try {
			if ( empty( $firebase_uid ) || '' === $new_password ) {
				throw new \Exception( 'Need firebase_uid and password.', 400 );
			}

			$updated_user = $this->auth->changeUserPassword( $firebase_uid, $new_password );
		} catch ( \Kreait\Firebase\Exception\InvalidArgumentException $e ) {
			// TODO: Log error.
			throw new \Exception( 'Could not update user password.', 400 );
		}

		if ( ! empty( $updated_user ) ) {
			return $updated_user;
		}

		return false;
	}

	/**
	 * Update a user email in Firebase
	 *
	 * @param string $firebase_uid Firebase unique ID.
	 * @param string $new_email New user email.
	 *
	 * @throws \Exception $e Errors.
	 */
	private function update_email( $firebase_uid = null, $new_email = '' ) {
		try {
			if ( empty( $firebase_uid ) || '' === $new_email ) {
				throw new \Exception( 'Need firebase_uid and email', 400 );
			}

			$updated_user = $this->auth->changeUserEmail( $firebase_uid, $new_email );

			// TODO: catch exception for if email already exists.
			// - Find user that already exists and pass it along.

		} catch ( \Kreait\Firebase\Exception\InvalidArgumentException $e ) {
			// TODO: Log error.
			throw new \Exception( 'Could not update user email.', 400 );
		}

		if ( ! empty( $updated_user ) ) {
			return $updated_user;
		}

		return false;
	}
}
