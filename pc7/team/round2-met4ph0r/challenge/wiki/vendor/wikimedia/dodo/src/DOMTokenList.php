<?php

declare( strict_types=1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;

/**
 * DOMTokenList
 *
 * Note that duplicates are permitted!
 *
 * @see https://dom.spec.whatwg.org/#domtokenlist
 * @package Wikimedia\Dodo
 * @phan-forbid-undeclared-magic-properties
 */
class DOMTokenList implements \Wikimedia\IDLeDOM\DOMTokenList {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\DOMTokenList;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\DOMTokenList;

	/**
	 * Associated element
	 * @var Element
	 */
	private $_element;

	/**
	 * Associated attribute name
	 * @var string
	 */
	private $_name;

	/**
	 * Ordered list of tokens
	 *
	 * @var string[]
	 */
	private $_list = [];

	/**
	 * Last serialized value.
	 *
	 * @var ?string
	 */
	private $_lastStringValue = null;

	/**
	 * @param Element $element The element associated with this token list
	 * @param string $localName The name of the attribute associated with
	 *  this token list.
	 */
	public function __construct( Element $element, string $localName ) {
		$this->_element = $element;
		$this->_name = $localName;
		$this->_getList();
	}

	/**
	 * Fetch the attribute value and parse it into an ordered set.
	 * @param ?string $newValue
	 */
	public function _getList( ?string $newValue = null ): void {
		$value = $newValue ?? $this->getValue();
		if ( $value === $this->_lastStringValue ) {
			return;
		}
		$this->_parse( $value );
	}

	/**
	 * @param string $value
	 * @see https://dom.spec.whatwg.org/#concept-ordered-set-parser
	 */
	private function _parse( string $value ): void {
		$this->_list = [];
		$this->_lastStringValue = $value;
		$seen = [ '' => true ];
		foreach ( preg_split( '/[ \t\r\n\f]+/', $value ) as $token ) {
			if ( !( $seen[$token] ?? false ) ) {
				$this->_list[] = $token;
				$seen[$token] = true;
			}
		}
	}

	/**
	 * @see https://dom.spec.whatwg.org/#concept-dtl-update
	 */
	private function _update() {
		$this->_lastStringValue = implode( ' ', $this->_list );
		if ( count( $this->_list ) === 0 &&
			 !$this->_element->hasAttribute( $this->_name ) ) {
			return;
		}
		$this->_element->setAttribute(
			$this->_name, $this->_lastStringValue
		);
	}

	/**
	 * Check that the token is not the empty string and does not have
	 * ASCII whitespace in it.
	 * @param string $token
	 */
	private function _validate( string $token ): void {
			if ( $token === '' ) {
				Util::error( "SyntaxError" );
			}
			if ( strlen( $token ) !== strcspn( $token, "\t\r\n\f " ) ) {
				Util::error( "InvalidCharacterError" );
			}
	}

	/**
	 * @param string ...$tokens
	 */
	public function add( string ...$tokens ): void {
		foreach ( $tokens as $token ) {
			$this->_validate( $token );
		}

		foreach ( $tokens as $token ) {
			if ( !in_array( $token, $this->_list, true ) ) {
				$this->_list[] = $token;
			}
		}

		$this->_update();
	}

	/**
	 * @param string $token
	 *
	 * @return bool
	 */
	public function contains( string $token ): bool {
		// No error checking on $token validity, as per spec
		return in_array( $token, $this->_list, true );
	}

	/**
	 *
	 * @param string ...$tokens
	 */
	public function remove( string ...$tokens ): void {
		foreach ( $tokens as $token ) {
			$this->_validate( $token );
		}

		foreach ( $tokens as $token ) {
			$this->_list = array_filter( $this->_list, static function ( $e ) use ( $token ){
				return $e !== $token;
			} );
		}

		$this->_update();
	}

	/**
	 *
	 * @param string $token
	 * @param string $newToken
	 *
	 * @return bool
	 */
	public function replace( string $token, string $newToken ): bool {
		// Note that the spec says SyntaxErrors must be thrown *before*
		// InvalidCharacterErrors
		if ( $newToken === '' ) {
			Util::error( 'SyntaxError' );
		}
		$this->_validate( $token );
		$this->_validate( $newToken );

		$idx = array_search( $token, $this->_list, true );
		if ( $idx === false ) {
			// per spec, we do not run the update steps on this path
			return false;
		}
		$idx2 = array_search( $newToken, $this->_list, true );
		if ( $idx2 === false ) {
			$this->_list[$idx] = $newToken;
		} else {
			// "replace the first instance of either token or newToken
			// with newToken and remove all other instances"
			if ( $idx < $idx2 ) {
				$this->_list[$idx] = $newToken;
				array_splice( $this->_list, $idx2, 1 );
			} else {
				// $idx2 is already newToken
				array_splice( $this->_list, $idx, 1 );
			}
		}
		$this->_update();
		return true;
	}

	/**
	 * @return string
	 */
	public function getValue(): string {
		return $this->_element->getAttribute( $this->_name ) ?? '';
	}

	/**
	 * @param string $val
	 */
	public function setValue( string $val ): void {
		$this->_element->setAttribute( $this->_name, $val );
	}

	/**
	 * Count the names
	 *
	 * @return int
	 */
	public function getLength(): int {
		return count( $this->_list );
	}

	/**
	 * @param int $index Index
	 *
	 * @return string|null
	 */
	public function item( int $index ): ?string {
		return $this->_list[ $index ] ?? null;
	}

	/**
	 *
	 * @param string $token Name
	 * @param bool|null $force
	 *
	 * @return bool
	 */
	public function toggle( string $token, ?bool $force = null ): bool {
		$this->_validate( $token );
		if ( $this->contains( $token ) ) {
			if ( $force !== true ) {
				$this->remove( $token );
				return false;
			}
			return true;
		} elseif ( $force !== false ) {
			$this->add( $token );
			return true;
		}
		return false;
	}
}
