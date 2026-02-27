<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Throwable;
use Wikimedia\Dodo\DOMException;
use Wikimedia\Dodo\Element;
use Wikimedia\IDLeDOM\ParentNode;
use Wikimedia\Zest\ZestInst;

/**
 * Our own customized Zest instance.
 */
class Zest {
	/** @var ZestInst */
	private static $singleton = null;

	private static function singleton() {
		if ( !self::$singleton ) {
			self::$singleton = new class extends ZestInst {
				/** @inheritDoc */
				protected function getElementById( $context, string $id, array $opts = [] ): array {
					// Dodo-internal method!
					return $context->_getElementsById( $id );
				}

				/** @inheritDoc */
				protected function isStandardsMode( $context, array $opts ): bool {
					return true;
				}

				/** @inheritDoc */
				protected function newBadSelectorException( string $msg ): Throwable {
					return new DOMException( $msg, 'SyntaxError' );
				}
			};
		}
		return self::$singleton;
	}

	/**
	 * Find elements matching a CSS selector underneath $context.
	 * @param string $sel The CSS selector string
	 * @param ParentNode $context
	 *   The scoping root for the search
	 * @return array<Element> Elements matching the CSS selector
	 */
	public static function find( string $sel, $context ): array {
		// Zest declares its types as if they were \DOMDocument, etc, but
		// we're going to pass it Dodo types.
		// @phan-suppress-next-line PhanTypeMismatchArgument,PhanTypeMismatchReturn
		return self::singleton()->find( $sel, $context );
	}

	/**
	 * Determine whether an element matches the given selector.
	 * @param Element $el The element to be tested
	 * @param string $sel The CSS selector string
	 * @return bool True iff the element matches the selector
	 */
	public static function matches( $el, string $sel ): bool {
		// Zest declares its types as if they were \DOMDocument, etc, but
		// we're going to pass it Dodo types.
		// @phan-suppress-next-line PhanTypeMismatchArgument
		return self::singleton()->matches( $el, $sel );
	}

	/**
	 * Get descendants by ID.
	 * The PHP DOM doesn't provide this method for DOMElement, and the
	 * implementation in DOMDocument is broken.
	 *
	 * @param ParentNode $context
	 *   The scoping root for the search
	 * @param string $id
	 * @return array<Element> A list of the elements with the given ID.
	 */
	public static function getElementsById( $context, string $id ): array {
		// Zest declares its types as if they were \DOMDocument, etc, but
		// we're going to pass it Dodo types.
		// @phan-suppress-next-line PhanTypeMismatchArgument,PhanTypeMismatchReturn
		return self::singleton()->getElementsById( $context, $id );
	}

	/**
	 * Get descendants by tag name.
	 *
	 * @param ParentNode $context
	 * @param string $tagName
	 * @return array<Element>
	 */
	public static function getElementsByTagName( $context, string $tagName ) {
		// Zest declares its types as if they were \DOMDocument, etc, but
		// we're going to pass it Dodo types.
		// @phan-suppress-next-line PhanTypeMismatchArgument,PhanTypeMismatchReturn
		return self::singleton()->getElementsByTagName( $context, $tagName );
	}

}
