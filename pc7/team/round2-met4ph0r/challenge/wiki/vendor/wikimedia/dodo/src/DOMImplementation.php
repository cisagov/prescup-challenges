<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;

/**
 * The DOMImplementation interface represents an object providing methods
 * which are not dependent on any particular document. Such an object is
 * available in the Document->implementation property.
 *
 * PORT NOTES:
 *
 * Removes:
 *       public function mozSetOutputMutationHandler($doc, $handler)
 *       public function mozGetInputMutationHandler($doc)
 *       public $mozHTMLParser = HTMLParser;
 *
 * Renames:
 * Changes:
 *      - supportedFeatures array was moved to a static variable inside of
 *        DOMImplementation->hasFeature(), and renamed to $supported.
 *
 * Each Document must have its own instance of
 * a DOMImplementation object
 * @phan-forbid-undeclared-magic-properties
 */
class DOMImplementation implements \Wikimedia\IDLeDOM\DOMImplementation {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\DOMImplementation;
	use UnimplementedTrait;

	/**
	 * @var Document
	 */
	private $_contextObject;

	/**
	 * @param Document|null $contextObject
	 */
	public function __construct( ?Document $contextObject = null ) {
		$this->_contextObject = $contextObject ?? new Document();
	}

	/**
	 * hasFeature()
	 * @param string $feature a string corresponding to a key in $supportedFeatures
	 * @param string|null $version [optional] a string corresponding to a version in $supportedFeatures
	 *
	 * @return bool Always returns true.
	 */
	public function hasFeature( string $feature = "", ?string $version = "" ): bool {
		// hasFeature() originally would report whether the user agent
		// claimed to support a given DOM feature, but experience
		// proved it was not nearly as reliable or granular as simply
		// checking whether the desired objects, attributes, or methods
		// existed. As such, it is no longer to be used, but continues
		// to exist (and simply returns true) so that old pages don’t
		// stop working.
		return true;
	}

	/** @inheritDoc */
	public function createDocumentType( string $qualifiedName, string $publicId = '', string $systemId = '' ) {
		if ( !$this->isValidQName( $qualifiedName ) ) {
			Util::error( 'Invalid qualified name.', 'InvalidCharacterError' );
		}

		return new DocumentType(
			$this->_contextObject,
			$qualifiedName,
			$publicId,
			$systemId );
	}

	/**
	 * @param string $qualifiedName
	 * @return bool
	 */
	private function isValidQName( string $qualifiedName ): bool {
		// $qualifiedName = $this->checkEncoding($qualifiedName);
		return (bool)preg_match(
			'/^([a-z_\x80-\xff]+[a-z0-9._\x80-\xff-]*:)?[a-z_\x80-\xff]+[a-z0-9._\x80-\xff-]*$/i',
			$qualifiedName
		);
	}

	/**
	 * TODO implement this
	 *
	 * @param string $str
	 *
	 * @return mixed
	 */
	private function checkEncoding( $str ) {
		/**
		 *
		 */

		return $str;
	}

	/** @inheritDoc */
	public function createDocument( ?string $namespace, ?string $qualifiedName = '', $doctype = null ) {
		/*
		 * Note that the current DOMCore spec makes it impossible
		 * to create an "HTML document" with this function, even if
		 * the namespace and doctype are properly set. See thread:
		 * http://lists.w3.org/Archives/Public/www-dom/2011AprJun/0132.html
		 * Use ::createHTMLDocument() instead.
		 */
		if ( $namespace === Util::NAMESPACE_HTML ) {
			$contentType = "application/xhtml+xml";
		} elseif ( $namespace === Util::NAMESPACE_SVG ) {
			$contentType = "image/svg+xml";
		} else {
			$contentType = "application/xml";
		}

		$d = new XMLDocument(
			$this->_contextObject,
			$contentType
		);

		if ( $qualifiedName ) {
			$e = $d->createElementNS( $namespace, $qualifiedName );
		} else {
			$e = null;
		}

		if ( $doctype ) {
			$d->appendChild( $doctype );
		}

		if ( $e ) {
			$d->appendChild( $e );
		}

		return $d;
	}

	/** @inheritDoc */
	public function createHTMLDocument( ?string $titleText = null ) {
		$d = new Document();
		$d->_setOrigin( $this->_contextObject );
		$d->_setContentType( 'text/html', true );

		$d->appendChild( new DocumentType( $d, "html" ) );

		$html = $d->createElement( "html" );

		$d->appendChild( $html );

		$head = $d->createElement( "head" );

		$html->appendChild( $head );

		if ( $titleText !== null ) {
			$title = $d->createElement( "title" );
			$head->appendChild( $title );
			$title->appendChild( $d->createTextNode( $titleText ) );
		}

		$html->appendChild( $d->createElement( "body" ) );

		return $d;
	}
}
