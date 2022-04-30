<?php
declare(strict_types=1);

namespace Lcobucci\JWT\Validation\Constraint;

use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;

final class AuthTime implements Constraint
{
	public function __construct( $id_token_auth_time, $leeway = 1 ) {
		$this->id_token_auth_time = $id_token_auth_time;
		$this->leeway             = $leeway;
	}

	public function assert( Token $token ): void {
		if ( ! $token instanceof UnencryptedToken ) {
			throw new ConstraintViolation( 'You should pass a plain token' );
		}

		if ( ! $token->claims()->has( 'auth_time' ) ) {
			throw new ConstraintViolation( '"auth_time" claim missing' );
		}

		if ( abs( $this->id_token_auth_time - $token->claims()->get( 'auth_time' ) ) > $this->leeway ) {
			throw new ConstraintViolation( '"auth_time" claim is invalid' );
		}
	}
}
