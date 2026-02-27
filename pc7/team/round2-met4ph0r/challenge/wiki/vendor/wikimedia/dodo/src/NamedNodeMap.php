<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;

/**
 * NamedNodeMap.php
 * ----------------
 * Implements a NamedNodeMap. Used to represent Element::attributes.
 *
 * NOTE: Why is it called NamedNodeMap?
 *
 *      NamedNodeMap has nothing to do with Nodes, it's a collection
 *      of Attrs. But once upon a time, an Attr was a type of Node called a
 *      NamedNode. But then DOM-4 came along and said that an Attr is no
 *      longer a subclass of Node. But then DOM-LS came and change it again,
 *      and said it was a subclass of Node. NamedNode was forgotten, but it
 *      lives on in this interface's name! How confusing!
 *
 * NOTE:
 *      "Qualified name" is the "prefix:localName" string, which is what
 *      the "methods not ending in NS" use, aka Element::getAttribute()
 *      looks up by "qualified name".  Our code uses "qname" to refer
 *      to this. The "methods ending in NS" look up by a combination of
 *      namespace and local name (ignoring prefix) which this code calls
 *      a "nskey" (or $key for short).
 *
 *      There can be multiple attributes matching a given qname -- ie,
 *      they can have different namespaces for the same prefix so they
 *      collide in the `qname` index but not the `nskey` index.  The
 *      `nskey` index however should be unique: in all the paths that
 *      might seem to allow different prefixes for the same namespace
 *      the prefix is instead stored in the local name portion so that
 *      uniqueness of `nskey` is preserved.  We maintain a one-to-many
 *      map given the qname key. For the nskey maps we could use the
 *      index->attribute map to recompute the 'first' attribute for an
 *      nskey on every removal, although the uniqueness of the nskey means
 *      this isn't necessary in practice.
 *
 * NOTE: This looks different from Domino.js!
 *
 *      In Domino.js, NamedNodeMap was only implemented to satisfy
 *      'instanceof' type-checking. Almost all of the methods were
 *      stubbed, except for 'length' and 'item'. The tables that
 *      stored an Element's attributes were located directly on the
 *      Element itself.
 *
 *      Because there are so many attribute handling methods on an
 *      Element, each with little differences, this meant replicating
 *      a bunch of the book-keeping inside those methods. The negative
 *      impact on code maintainability was pronounced, so the book-keeping
 *      was transferred to the NamedNodeMap itself, and its methods were
 *      properly implemented, which made it much easier to read and write
 *      the attribute methods on the Element class.
 *
 * @phan-forbid-undeclared-magic-properties
 */
class NamedNodeMap implements \Wikimedia\IDLeDOM\NamedNodeMap {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\NamedNodeMap;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\NamedNodeMap;

	/**
	 * qname => Attr
	 *
	 * @var array<string,Attr|array<Attr>> entries are either Attr objects, or arrays of Attr objects on collisions
	 */
	private $_qnameToAttr = [];

	/**
	 * ns|lname => Attr
	 *
	 * @var array<string,Attr>
	 */
	private $_nskeyToAttr = [];

	/**
	 * ns|lname => index number
	 *
	 * @var array<string,int>
	 */
	private $_nskeyToIndex = [];

	/**
	 * index number => Attr
	 * @var array<int,Attr>
	 */
	private $_indexToAttr = [];

	/**
	 * DOM-LS associated element, defined in spec but not given property.
	 *
	 * @var ?Element
	 */
	private $_element = null;

	/**
	 * @param ?Element $element
	 */
	public function __construct( ?Element $element = null ) {
		$this->_element = $element;
	}

	/**********************************************************************
	 * DODO INTERNAL BOOK-KEEPING
	 */

	/**
	 * Helper function to return an 'nsKey' from an attribute.
	 * @param Attr $a
	 * @return string
	 */
	private function makeNsKey( Attr $a ): string {
		return self::makeNsKey2( $a->getNamespaceURI(), $a->getLocalName() );
	}

	/**
	 * Helper function to return an 'nsKey' from a namespace and local name.
	 * @param ?string $ns Namespace (null or non-empty string)
	 * @param string $lname Local name
	 * @return string
	 */
	private function makeNsKey2( ?string $ns, string $lname ): string {
		return ( $ns ?? '' ) . "|$lname";
	}

	/**
	 * Helper function to add an entry from the qname_to_attr map.
	 * @internal
	 * @param string $qname
	 * @param Attr $a
	 */
	private function addQnameToAttr( string $qname, Attr $a ): void {
		self::assert( $qname === $a->getName() );
		if ( isset( $this->_qnameToAttr[$qname] ) ) {
			if ( !is_array( $this->_qnameToAttr[$qname] ) ) {
				$this->_qnameToAttr[$qname] = [
					$this->_qnameToAttr[$qname]
				];
			}
			$this->_qnameToAttr[$qname][] = $a;
		} else {
			$this->_qnameToAttr[$qname] = $a;
		}
	}

	/**
	 * Helper function to remove an entry from the qname_to_attr map.
	 * @internal
	 * @param string $qname
	 * @param Attr $a
	 */
	private function removeQnameToAttr( string $qname, Attr $a ): void {
		self::assert( $qname === $a->getName() );
		self::assert( isset( $this->_qnameToAttr[$qname] ) );
		if ( is_array( $this->_qnameToAttr[$qname] ) ) {
			$i = array_search( $a, $this->_qnameToAttr[$qname], true );
			self::assert( $i !== false );
			array_splice( $this->_qnameToAttr[$qname], $i, 1 );
			if ( count( $this->_qnameToAttr[$qname] ) === 1 ) {
				$aa = $this->_qnameToAttr[$qname][0];
				$this->_qnameToAttr[$qname] = $aa;
			}
		} else {
			unset( $this->_qnameToAttr[$qname] );
		}
	}

	/**
	 * @internal
	 * @see https://dom.spec.whatwg.org/#concept-element-attributes-append
	 * @param Attr $a
	 */
	public function _append( Attr $a ): void {
		$a->_handleAttributeChanges(
			$this->_element, null, $a->getValue()
		);

		$qname = $a->getName();
		$this->addQnameToAttr( $qname, $a );

		$key = self::makeNsKey( $a );
		$i = count( $this->_indexToAttr );
		$this->_indexToAttr[] = $a;

		if ( !isset( $this->_nskeyToAttr[$key] ) ) {
			/* NO COLLISION */
			$this->_nskeyToAttr[$key] = $a;
			$this->_nskeyToIndex[$key] = $i;
		} else {
			/* COLLISION */
			// ignore: we've added to _indexToAttr, and that's enough.
			// (this should be impossible, nskey should be unique)
		}
		$a->_ownerElement = $this->_element;
	}

	/**
	 * @internal
	 * @see https://dom.spec.whatwg.org/#concept-element-attributes-replace
	 * @param Attr $oldAttr
	 * @param Attr $a
	 */
	public function _replace( Attr $oldAttr, Attr $a ) {
		$oldAttr->_handleAttributeChanges(
			$oldAttr->getOwnerElement(),
			$oldAttr->getValue(),
			$a->getValue()
		);

		$oldQname = $oldAttr->getName();
		$newQname = $a->getName();
		$this->removeQnameToAttr( $oldQname, $oldAttr );
		$this->addQnameToAttr( $newQname, $a );

		$key = self::makeNsKey( $a );
		self::assert( $key === self::makeNsKey( $oldAttr ) );
		$i = $this->_nskeyToIndex[$key];
		$this->_indexToAttr[$i] = $a;
		$this->_nskeyToAttr[$key] = $a;
	}

	/**
	 * @internal
	 * @see https://dom.spec.whatwg.org/#concept-element-attributes-remove
	 * @param Attr $a
	 */
	public function _remove( Attr $a ): void {
		$qname = $a->getName();
		$key = self::makeNsKey( $a );

		self::assert( isset( $this->_qnameToAttr[$qname] ) );
		self::assert( isset( $this->_nskeyToAttr[$key] ) );
		self::assert( isset( $this->_nskeyToIndex[$key] ) );

		$a->_handleAttributeChanges( $this->_element, $a->getValue(), null );

		$this->removeQnameToAttr( $qname, $a );

		unset( $this->_nskeyToAttr[$key] );
		$i = $this->_nskeyToIndex[$key];
		unset( $this->_nskeyToIndex[$key] );
		array_splice( $this->_indexToAttr, $i, 1 );
		// Reassign in reverse order, since the _nskeyToIndex and
		// _nskeyToAttr is supposed to contain the *first* attribute of
		// a given nskey.
		for ( $j = count( $this->_indexToAttr ) - 1; $j >= $i; $j-- ) {
			$a2 = $this->_indexToAttr[$j];
			$key2 = self::makeNsKey( $a2 );
			$this->_nskeyToIndex[$key2] = $j;
			// nskey is actually unique in this NamedNodeMap, so the following
			// line isn't strictly necessary: it would be necessary if the
			// $key deleted happend to be the same as $key2 here.  But
			// better safe than sorry...
			$this->_nskeyToAttr[$key2] = $a2;
		}

		$a->_ownerElement = null;
	}

	/*
	 * DOM-LS Methods
	 */

	/** @inheritDoc */
	public function getLength(): int {
		return count( $this->_indexToAttr );
	}

	/** @inheritDoc */
	public function item( int $index ) {
		return $this->_indexToAttr[$index] ?? null;
	}

	/**
	 * Nonstandard.
	 * @internal
	 * @param string $qname Qualified name
	 * @return bool
	 */
	public function _hasNamedItem( string $qname ): bool {
		/*
		 * Per HTML spec, we normalize qname before lookup,
		 * even though XML itself is case-sensitive.
		 */
		if ( !ctype_lower( $qname ) && $this->_element->_isHTMLElement() ) {
			$qname = Util::toAsciiLowercase( $qname );
		}

		return isset( $this->_qnameToAttr[$qname] );
	}

	/**
	 * Nonstandard.
	 * @internal
	 * @param ?string $ns Namespace
	 * @param string $lname Local name
	 * @return bool
	 */
	public function _hasNamedItemNS( ?string $ns, string $lname ): bool {
		$key = self::makeNsKey2( $ns, $lname );
		return isset( $this->_nskeyToAttr[$key] );
	}

	/**
	 * Nonstandard.
	 * @internal
	 * @param Attr $a
	 * @return bool
	 */
	public function _hasNamedItemNode( Attr $a ): bool {
		$qname = $a->getName();
		/*
		 * Per HTML spec, we normalize qname before lookup,
		 * even though XML itself is case-sensitive.
		 */
		if ( !ctype_lower( $qname ) && $this->_element->_isHTMLElement() ) {
			$qname = Util::toAsciiLowercase( $qname );
		}

		if ( !isset( $this->_qnameToAttr[$qname] ) ) {
			return false;
		}

		if ( is_array( $this->_qnameToAttr[$qname] ) ) {
			$i = array_search( $a, $this->_qnameToAttr[$qname], true );
			return ( $i !== false );
		} else {
			return $this->_qnameToAttr[$qname] === $a;
		}
	}

	/** @inheritDoc */
	public function getNamedItem( string $qname ): ?Attr {
		/*
		 * Per HTML spec, we normalize qname before lookup,
		 * even though XML itself is case-sensitive.
		 */
		if ( !ctype_lower( $qname ) && $this->_element->_isHTMLElement() ) {
			$qname = Util::toAsciiLowercase( $qname );
		}

		if ( !isset( $this->_qnameToAttr[$qname] ) ) {
			return null;
		}

		if ( is_array( $this->_qnameToAttr[$qname] ) ) {
			return $this->_qnameToAttr[$qname][0];
		} else {
			return $this->_qnameToAttr[$qname];
		}
	}

	/**
	 * The getNamedItemNS(namespace, localName) method steps are to
	 * return the result of *getting an attribute given namespace,
	 * localName, and element.*
	 * @inheritDoc
	 * @see https://dom.spec.whatwg.org/#dom-namednodemap-getnameditemns
	 * @see https://dom.spec.whatwg.org/#concept-element-attributes-get-by-namespace
	 */
	public function getNamedItemNS( ?string $ns, string $lname ): ?Attr {
		$key = self::makeNsKey2( $ns, $lname );
		return $this->_nskeyToAttr[$key] ?? null;
	}

	/**
	 * The setNamedItem(attr) and setNamedItemNS(attr) method steps are
	 * to return the result of "setting an attribute" given attr and element.
	 * @inheritDoc
	 * @see https://dom.spec.whatwg.org/#dom-namednodemap-setnameditem
	 * @see https://dom.spec.whatwg.org/#concept-element-attributes-set
	 */
	public function setNamedItem( $attr ) {
		'@phan-var Attr $attr'; // @var Attr $attr
		$owner = $attr->getOwnerElement();

		if ( $owner !== null && $owner !== $this->_element ) {
			Util::error( "InUseAttributeError" );
		}

		$oldAttr = $this->getNamedItemNS(
			$attr->getNamespaceURI(), $attr->getLocalName()
		);

		if ( $oldAttr == $attr ) {
			return $attr;
		}

		if ( $oldAttr !== null ) {
			$this->_replace( $oldAttr, $attr );
		} else {
			$this->_append( $attr );
		}

		return $oldAttr;
	}

	/** @inheritDoc */
	public function setNamedItemNS( $attr ) {
		return $this->setNamedItem( $attr );
	}

	/**
	 * Note: qname may be lowercase or normalized in various ways
	 *
	 * @see https://dom.spec.whatwg.org/#dom-namednodemap-removenameditem
	 * @inheritDoc
	 */
	public function removeNamedItem( string $qname ): Attr {
		$attr = $this->getNamedItem( $qname );
		if ( $attr !== null ) {
			'@phan-var Attr $attr'; // @var Attr $attr
			$this->_remove( $attr );
		} else {
			Util::error( "NotFoundError" );
			// Lie to phan about types since the above should never return
			'@phan-var Attr $attr'; // @var Attr $attr
		}
		return $attr;
	}

	/**
	 * Note: lname may be lowercase or normalized in various ways
	 *
	 * @see https://dom.spec.whatwg.org/#dom-namednodemap-removenameditemns
	 * @inheritDoc
	 */
	public function removeNamedItemNS( ?string $ns, string $lname ) {
		$attr = $this->getNamedItemNS( $ns, $lname );
		if ( $attr !== null ) {
			'@phan-var Attr $attr'; // @var Attr $attr
			$this->_remove( $attr );
		} else {
			Util::error( "NotFoundError" );
			// Lie to phan about types since the above should never return
			'@phan-var Attr $attr'; // @var Attr $attr
		}
		return $attr;
	}

	/**
	 * Little helper function to write simple assertions.
	 * Could go in a helper trait or something.
	 * @param bool $b
	 */
	private static function assert( bool $b ): void {
		if ( !$b ) {
			throw new \Error( "Impossible" );
		}
	}

}
