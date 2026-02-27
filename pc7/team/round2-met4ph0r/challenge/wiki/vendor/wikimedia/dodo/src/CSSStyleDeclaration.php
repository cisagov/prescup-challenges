<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class CSSStyleDeclaration implements \Wikimedia\IDLeDOM\CSSStyleDeclaration {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\CSSStyleDeclaration;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\CSSStyleDeclaration {
		__set as protected _setHelper;
	}

	/**
	 * Hack! Allow (and ignore) any property access to set.
	 * @param string $name
	 * @param mixed $value
	 */
	public function __set( string $name, $value ): void {
		switch ( $name ) {
		case 'cssText':
		case 'cssFloat':
			$this->_setHelper( $name, $value );
			return;
		default:
			/* Cheerfully ignore this! */
			return;
		}
	}
}
