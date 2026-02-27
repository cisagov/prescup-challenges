<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Exception;

/**
 * Exception thrown when DOM API functionality which is not (or not yet)
 * implemented in Dodo is used.
 */
class UnimplementedException extends Exception {
	/**
	 * Create a new UnimplementedException.
	 *
	 * @param string $message
	 */
	public function __construct( string $message = "Unimplemented" ) {
		parent::__construct( $message );
	}
}
