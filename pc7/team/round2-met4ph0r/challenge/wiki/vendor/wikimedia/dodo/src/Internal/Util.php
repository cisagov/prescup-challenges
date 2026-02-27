<?php

declare( strict_types = 1 );
// phpcs:disable PSR12.Properties.ConstantVisibility.NotFound

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\DOMException;

/******************************************************************************
 * Util.php
 * -------------
 * Define namespace-global constants and functions (mostly error-handling).
 */
class Util {

	/******************************************************************************
	 * CONSTANTS
	 * ---------
	 * The various W3C and WHATWG recommendations define a number of
	 * constants. Although these are usually associated with a particular
	 * interface, we collect all of them here for convenience.
	 */

	/**
	 * NAMESPACE_*
	 * Strings defining the various document namespaces
	 * [DODO] These are used by this library and aren't part of a spec.
	 */
	const NAMESPACE_HTML = "http://www.w3.org/1999/xhtml";
	const NAMESPACE_XML = "http://www.w3.org/XML/1998/namespace";
	const NAMESPACE_XMLNS = "http://www.w3.org/2000/xmlns/";
	const NAMESPACE_MATHML = "http://www.w3.org/1998/Math/MathML";
	const NAMESPACE_SVG = "http://www.w3.org/2000/svg";
	const NAMESPACE_XLINK = "http://www.w3.org/1999/xlink";

	/**
	 * Original:
	 * throw new Error("Assertion failed: " + (msg || "") + "\n" new Error().stack);
	 *
	 * TODO: Need to add the stack trace info, or advise catchers call
	 * Exception::getTraceAsString()
	 *
	 * TODO: Make this a true PHP assert?
	 *
	 * @param bool $condition
	 * @param ?string $message
	 * @throws \Exception
	 * @phan-assert-true-condition $condition
	 */
	public static function assert( bool $condition, ?string $message = "" ) {
		if ( !$condition ) {
			throw new \Exception( "Assert failed: $message" );
		}
	}

	/**
	 * Throw a DOMException
	 *
	 * @param string $name one of the values below
	 * @param string|null $message an optional message to include in the Exception
	 * @throws DOMException
	 *
	 * NOTE
	 * Allowed values for $string are: IndexSizeError, HierarchyRequestError
	 * WrongDocumentError, InvalidCharacterError, NoModificationAllowedError,
	 * NotFoundError, NotSupportedError, InvalidStateError, SyntaxError,
	 * InvalidModificationError, NamespaceError, InvalidAccessError,
	 * TypeMismatchError, SecurityError, NetworkError, AbortError,
	 * UrlMismatchError, QuotaExceededError, TimeoutError,
	 * InvalidNodeTypeError, and DataCloneError
	 *
	 * For more information, see interfaces/DOMException.php
	 * @return never
	 */
	public static function error( string $name, ?string $message = null ) {
		throw new DOMException( $message, $name );
	}

	/******************************************************************************
	 * TEXT FORMATTING
	 */

	/**
	 * ASCII lowercase a string.
	 *
	 * @see https://infra.spec.whatwg.org/#ascii-lowercase
	 *
	 * @param string $s
	 * @return string
	 */
	public static function toAsciiLowercase( string $s ): string {
		// Note that strtolower depends on the locale set in the environment,
		// aka https://www.php.net/manual/en/function.strtolower.php says
		// "Note that 'alphabetic' is determined by the current locale."
		// and mb_strtolower() is up to 30x slower.  The DOM spec is
		// deliberately minimalistic.
		return strtr(
			$s,
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
			"abcdefghijklmnopqrstuvwxyz"
		);
	}

	/**
	 * ASCII uppercase a string.
	 *
	 * @see https://infra.spec.whatwg.org/#ascii-uppercase
	 *
	 * @param string $s
	 * @return string
	 */
	public static function toAsciiUppercase( string $s ): string {
		// Note that strtoupper depends on the locale set in the environment,
		// aka https://www.php.net/manual/en/function.strtoupper.php says
		// "Note that 'alphabetic' is determined by the current locale."
		// and mb_strtoupper() is up to 30x slower.  The DOM spec is
		// deliberately minimalistic.
		return strtr(
			$s,
			"abcdefghijklmnopqrstuvwxyz",
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		);
	}

	/**
	 * "Strip and collapse ASCII whitespace"
	 * @see https://infra.spec.whatwg.org/#strip-and-collapse-ascii-whitespace
	 * @param string $s
	 * @return string
	 */
	public static function stripAndCollapseWhitespace( string $s ): string {
		$s = preg_replace( '/[ \t\n\r\f]+/', ' ', $s );
		$s = preg_replace( '/(^ )|( $)/', '', $s );
		return $s;
	}
}
