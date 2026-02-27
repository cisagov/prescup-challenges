<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\FilteredElementList;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;
use Wikimedia\Dodo\Internal\WhatWG;
use Wikimedia\Dodo\Internal\Zest;
use Wikimedia\IDLeDOM\Attr as IAttr;

/**
 * Element.php
 *
 * Defines an "Element"
 *
 * Where a specification is implemented, the following annotations appear.
 *
 * DOM-1     W3C DOM Level 1 		     http://w3.org/TR/DOM-Level-1/
 * DOM-2     W3C DOM Level 2 Core	     http://w3.org/TR/DOM-Level-2-Core/
 * DOM-3     W3C DOM Level 3 Core	     http://w3.org/TR/DOM-Level-3-Core/
 * DOM-4     W3C DOM Level 4 		     http://w3.org/TR/dom/
 * DOM-LS    WHATWG DOM Living Standard      http://dom.spec.whatwg.org/
 * DOM-PS-WD W3C DOM Parsing & Serialization http://w3.org/TR/DOM-Parsing/
 * WEBIDL-1  W3C WebIDL Level 1	             http://w3.org/TR/WebIDL-1/
 * XML-NS    W3C XML Namespaces		     http://w3.org/TR/xml-names/
 * CSS-OM    CSS Object Model                http://drafts.csswg.org/cssom-view/
 * HTML-LS   HTML Living Standard            https://html.spec.whatwg.org/
 *
 */
class Element extends ContainerNode implements \Wikimedia\IDLeDOM\Element {
	// DOM mixins
	use ChildNode;
	use NonDocumentTypeChildNode;
	use ParentNode;
	use Slottable;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\Element;
	use \Wikimedia\IDLeDOM\Stub\InnerHTML;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Element;

	/*
	* Qualified Names, Local Names, and Namespace Prefixes
	*
	* An Element or Attribute's qualified name is its local name if its
	* namespace prefix is null, and its namespace prefix, followed by ":",
	* followed by its local name, otherwise.
	*/

	// XXX figure out how to save storage by only storing this for
	// HTMLUnknownElement etc; for specific HTML*Element subclasses
	// we should be able to get this from the object type.
	// Split Element into AbstractElement and Element, where only
	// element has these fields; then
	// HTMLElement extends HTMLAbstractElement extends AbstractElement
	// where HTMLElement has these fields; then every class which
	// maps 1:1 on a particular localName will extend HTMLAbstractElement
	// not HTMLElement.
	// _prefix is in AbstractElement (since even HTML interfaces may have
	//   arbitrary prefixes in some documents; this is harder to factor out)
	// _namespaceURI and _localName are in Element
	// _localName is in HTMLElement (since every HTML element hard codes the
	//   namespace)
	// _nodeName is always computed, never stored.

	/** @var ?string */
	private $_namespaceURI = null;
	/** @var string */
	private $_localName;
	/** @var ?string */
	private $_prefix = null;

	/**
	 * @var ?NamedNodeMap Attribute storage; null if no attributes
	 */
	public $_attributes = null;

	/**
	 * A registry of handlers for changes to specific attributes.
	 * @var array<string,callable>|null
	 */
	public static $_attributeChangeHandlers = null;

	/**
	 * Fetch the appropriate attribute change handler for a change to the
	 * attribute named `$localName`.
	 * @param string $localName
	 * @return ?callable(Element,?string,?string):void
	 */
	public static function _attributeChangeHandlerFor( string $localName ) {
		if ( self::$_attributeChangeHandlers === null ) {
			self::$_attributeChangeHandlers = [
				"id" => static function ( $elem, $old, $new ) {
					if ( !$elem->getIsConnected() ) {
						return;
					}
					if ( $old !== null ) {
						$elem->_nodeDocument->_removeFromIdTable( $old, $elem );
					}
					// Note that the empty string is not a valid ID.
					// https://dom.spec.whatwg.org/#concept-id
					if ( $new !== null && $new !== '' ) {
						$elem->_nodeDocument->_addToIdTable( $new, $elem );
					}
				},
				"class" => static function ( $elem, $old, $new ) {
					if ( $elem->_classList !== null ) {
						$elem->_classList->_getList( $new );
					}
				},
			];
		}
		return self::$_attributeChangeHandlers[$localName] ?? null;
	}

	/**
	 * @var ?DOMTokenList
	 */
	private $_classList = null;

	/**
	 * Element constructor
	 *
	 * @param Document $nodeDocument
	 * @param string $lname
	 * @param ?string $ns
	 * @param ?string $prefix
	 * @return void
	 */
	public function __construct( Document $nodeDocument, string $lname, ?string $ns, ?string $prefix = null ) {
		parent::__construct( $nodeDocument );

		/*
		 * DOM-LS: "Elements have an associated namespace, namespace
		 * prefix, local name, custom element state, custom element
		 * definition, is value. When an element is created, all of
		 * these values are initialized.
		 */
		$this->_namespaceURI  = $ns;
		$this->_prefix        = $prefix;
		$this->_localName     = $lname;

		/*
		 * DOM-LS: "Elements also have an attribute list, which is
		 * a list exposed through a NamedNodeMap. Unless explicitly
		 * given when an element is created, its attribute list is
		 * empty."
		 */
		$this->_attributes = null; // save space if no attributes
	}

	/**********************************************************************
	 * ACCESSORS
	 */

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::ELEMENT_NODE;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeName(): string {
		// NOTE that if you're tempted to cache this, keep in mind that
		// $this->_isHTMLElement() below *can change* when this node is
		// adopted into a different document (one document can be an
		// "HTML document" and the other not) which would change the
		// case of the value returned here.  You will need to add code
		// to _resetNodeDocument() to invalidate your cache.

		// On the other hand, a cache just of the toAsciiUppercase conversion
		// (taking advantage of the limited # of possible values seen here)
		// should be perfecty safe.
		static $upperCache = [];

		$prefix = $this->getPrefix();
		$lname = $this->getLocalName();
		/*
		 * DOM-LS: "An Element's qualified name is its local name
		 * if its namespace prefix is null, and its namespace prefix,
		 * followed by ":", followed by its local name, otherwise."
		 */
		$qname = ( $prefix === null ) ? $lname : ( $prefix . ':' . $lname );
		if ( $this->_isHTMLElement() ) {
			if ( !array_key_exists( $qname, $upperCache ) ) {
				$upperCache[$qname] = Util::toAsciiUppercase( $qname );
			}
			return $upperCache[$qname];
		}
		return $qname;
	}

	/**
	 * @return NamedNodeMap
	 */
	public function getAttributes(): NamedNodeMap {
		if ( $this->_attributes === null ) {
			$this->_attributes = new NamedNodeMap( $this );
		}
		return $this->_attributes;
	}

	/** @inheritDoc */
	public function getPrefix(): ?string {
		return $this->_prefix;
	}

	/** @inheritDoc */
	public function getLocalName(): string {
		return $this->_localName;
	}

	/** @inheritDoc */
	public function getNamespaceURI(): ?string {
		return $this->_namespaceURI;
	}

	/** @inheritDoc */
	final public function getTagName(): string {
		return $this->getNodeName();
	}

	/**
	 * @see https://w3c.github.io/DOM-Parsing/#the-innerhtml-mixin
	 * @return string
	 */
	public function getInnerHTML(): string {
		$result = [];
		if ( $this->_nodeDocument->_isHTMLDocument() ) {
			// "HTML fragment serialization algorithm"
			$this->_htmlSerialize( $result, [] );
		} else {
			// see https://github.com/w3c/DOM-Parsing/issues/28
			$options = [ 'requireWellFormed' => true ];
			for ( $node = $this->getFirstChild(); $node !== null; $node = $node->getNextSibling() ) {
				WhatWG::xmlSerialize( $node, $options, $result );
			}
		}
		return implode( '', $result );
	}

	/**
	 * @see https://w3c.github.io/DOM-Parsing/#dom-element-outerhtml
	 * @return string
	 */
	public function getOuterHTML(): string {
		$result = [];
		if ( $this->_nodeDocument->_isHTMLDocument() ) {
			// "HTML fragment serialization algorithm"
			WhatWG::htmlSerialize( $result, $this, null, [] );
		} else {
			// see https://github.com/w3c/DOM-Parsing/issues/28
			WhatWG::xmlSerialize( $this, [ 'requireWellFormed' => true ], $result );
		}
		return implode( '', $result );
	}

	/*
	* PHP compatibility
	*/

	/** @inheritDoc */
	public function setIdAttribute( string $qualifiedName, bool $isId ): void {
		/* Ignore this method, it is not necessary in an HTML DOM. */
	}

	/*
	 * METHODS DELEGATED FROM NODE
	 */

	/** @return Element */
	protected function _subclassCloneNodeShallow(): Node {
		/*
		 * XXX:
		 * Modify this to use the constructor directly or avoid
		 * error checking in some other way. In case we try
		 * to clone an invalid node that the parser inserted.
		 */
		if ( $this->getNamespaceURI() !== Util::NAMESPACE_HTML
			 || $this->getPrefix()
			 || !$this->_nodeDocument->_isHTMLDocument() ) {
			if ( $this->getPrefix() === null ) {
				$name = $this->getLocalName();
			} else {
				$name = $this->getPrefix() . ':' . $this->getLocalName();
			}
			$clone = $this->_nodeDocument->createElementNS(
				$this->getNamespaceURI(),
				$name
			);
		} else {
			$clone = $this->_nodeDocument->createElement(
				$this->getLocalName()
			);
		}
		'@phan-var Element $clone'; // @var Element $clone

		if ( $this->_attributes !== null ) {
			foreach ( $this->_attributes as $a ) {
				// @phan-suppress-next-line PhanTypeMismatchArgumentSuperType
				$clone->setAttributeNodeNS( $a->cloneNode() );
			}
		}

		return $clone;
	}

	/** @inheritDoc */
	protected function _subclassIsEqualNode( Node $node ): bool {
		if ( ( !( $node instanceof Element ) )
			 || $this->getLocalName() !== $node->getLocalName()
			 || $this->getNamespaceURI() !== $node->getNamespaceURI()
			 || $this->getPrefix() !== $node->getPrefix()
			 || count( $this->_attributes ?? [] ) !== count( $node->_attributes ?? [] ) ) {
			return false;
		}

		/*
		 * Compare the sets of attributes, ignoring order
		 * and ignoring attribute prefixes.
		 */
		foreach ( ( $this->_attributes ?? [] ) as $a ) {
			if ( !$node->hasAttributeNS( $a->getNamespaceURI(), $a->getLocalName() ) ) {
				return false;
			}
			if ( $node->getAttributeNS( $a->getNamespaceURI(), $a->getLocalName() ) !== $a->getValue() ) {
				return false;
			}
		}
		return true;
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		// Relocated to WhatWG::xmlSerializeElement because this method
		// was huge!
		WhatWG::xmlSerializeElement(
			$this, $namespace, $prefixMap, $prefixIndex,
			$options, $markup
		);
	}

	/*
	 * ATTRIBUTE: get/set/remove/has/toggle
	 */

	/**
	 * Fetch the value of an attribute with the given qualified name
	 *
	 * @param string $qname The attribute's qualifiedName
	 * @return ?string the value of the attribute
	 */
	public function getAttribute( string $qname ): ?string {
		if ( $this->_attributes === null ) {
			return null;
		}
		$attr = $this->_attributes->getNamedItem( $qname );
		return $attr ? $attr->getValue() : null;
	}

	/**
	 * Set the value of first attribute with a particular qualifiedName
	 *
	 * spec DOM-LS
	 *
	 * NOTES
	 * Per spec, $value is not a string, but the string value of
	 * whatever is passed.
	 *
	 * TODO: DRY with this and setAttributeNS?
	 *
	 * @inheritDoc
	 */
	public function setAttribute( string $qname, string $value ): void {
		if ( !WhatWG::is_valid_xml_name( $qname ) ) {
			Util::error( "InvalidCharacterError" );
		}

		if ( !ctype_lower( $qname ) && $this->_isHTMLElement() ) {
			$qname = Util::toAsciiLowercase( $qname );
		}
		$this->_setAttribute( $qname, $value );
	}

	/**
	 * Internal version of ::setAttribute() which bypasses checks and
	 * lowercasing; used by Remex when tree building.
	 * @param string $qname
	 * @param string $value
	 */
	public function _setAttribute( string $qname, string $value ): void {
		$attributes = $this->getAttributes();
		$attr = $attributes->getNamedItem( $qname );
		if ( $attr === null ) {
			$attr = new Attr( $this->_nodeDocument, $this, $qname, null, null, $value );
			$attributes->_append( $attr );
		} else {
			$attr->setValue( $value ); /* Triggers _handleAttributeChanges */
		}
	}

	/**
	 * Remove the first attribute given a particular qualifiedName
	 *
	 * spec DOM-LS
	 *
	 * @param string $qname
	 */
	public function removeAttribute( string $qname ): void {
		if ( $this->_attributes !== null ) {
			$attr = $this->_attributes->getNamedItem( $qname );
			if ( $attr !== null ) {
				// This throws an exception if the attribute is not found!
				$this->_attributes->_remove( $attr );
			}
		}
	}

	/**
	 * Test Element for attribute with the given qualified name
	 *
	 * spec DOM-LS
	 *
	 * @param string $qname Qualified name of attribute
	 * @return bool
	 */
	public function hasAttribute( string $qname ): bool {
		if ( $this->_attributes === null ) {
			return false;
		}
		return $this->_attributes->_hasNamedItem( $qname );
	}

	/**
	 * Toggle the first attribute with the given qualified name
	 *
	 * spec DOM-LS
	 *
	 * @param string $qname qualified name
	 * @param bool|null $force whether to set if no attribute exists
	 * @return bool whether we set or removed an attribute
	 */
	public function toggleAttribute( string $qname, ?bool $force = null ): bool {
		if ( !WhatWG::is_valid_xml_name( $qname ) ) {
			Util::error( "InvalidCharacterError" );
		}

		$a = $this->getAttributes()->getNamedItem( $qname );

		if ( $a === null ) {
			if ( $force === null || $force ) {
				$this->setAttribute( $qname, "" );
				return true;
			}
			return false;
		} else {
			if ( $force === null || !$force ) {
				$this->removeAttribute( $qname );
				return false;
			}
			return true;
		}
	}

	/**********************************************************************
	 * ATTRIBUTE NS: get/set/remove/has
	 */

	/**
	 * Fetch value of attribute with the given namespace and localName
	 *
	 * spec DOM-LS
	 *
	 * @param ?string $ns The attribute's namespace
	 * @param string $lname The attribute's local name
	 * @return ?string the value of the attribute
	 */
	public function getAttributeNS( ?string $ns, string $lname ): ?string {
		if ( $this->_attributes === null ) {
			return null;
		}
		$attr = $this->_attributes->getNamedItemNS( $ns, $lname );
		return $attr ? $attr->getValue() : null;
	}

	/**
	 * Set value of attribute with a particular namespace and localName
	 *
	 * spec DOM-LS
	 *
	 * NOTES
	 * Per spec, $value is not a string, but the string value of
	 * whatever is passed.
	 *
	 * @inheritDoc
	 */
	public function setAttributeNS( ?string $ns, string $qname, string $value ): void {
		$lname = null;
		$prefix = null;

		WhatWG::validate_and_extract( $ns, $qname, $prefix, $lname );
		$this->_setAttributeNS( $ns, $prefix, $lname, $value );
	}

	/**
	 * Internal version of ::setAttributeNS which bypasses checks and prefix
	 * parsing; used by Remex when tree building.
	 * @param ?string $ns
	 * @param ?string $prefix
	 * @param string $lname
	 * @param string $value
	 */
	public function _setAttributeNS( ?string $ns, ?string $prefix, string $lname, string $value ) {
		$attributes = $this->getAttributes();
		$attr = $attributes->getNamedItemNS( $ns, $lname );
		if ( $attr === null ) {
			$attr = new Attr( $this->_nodeDocument, $this, $lname, $prefix, $ns, $value );
			$attributes->_append( $attr );
		} else {
			$attr->setValue( $value );
		}
	}

	/**
	 * Remove attribute given a particular namespace and localName
	 *
	 * spec DOM-LS
	 *
	 * @inheritDoc
	 */
	public function removeAttributeNS( ?string $ns, string $lname ): void {
		if ( $this->_attributes !== null ) {
			$attr = $this->_attributes->getNamedItemNS( $ns, $lname );
			if ( $attr !== null ) {
				// This throws an exception if the attribute is not found!
				$this->_attributes->_remove( $attr );
			}
		}
	}

	/**
	 * Test Element for attribute with the given namespace and localName
	 *
	 * spec DOM-LS
	 *
	 * @param ?string $ns the namespace
	 * @param string $lname the localName
	 * @return bool
	 */
	public function hasAttributeNS( ?string $ns, string $lname ): bool {
		if ( $this->_attributes === null ) {
			return false;
		}
		return $this->_attributes->_hasNamedItemNS( $ns, $lname );
	}

	/*
	 * ATTRIBUTE NODE: get/set/remove
	 */

	/**
	 * Fetch the Attr node with the given qualifiedName
	 *
	 * spec DOM-LS
	 * @param string $qname The attribute's qualified name
	 * @return ?Attr the attribute node, or NULL
	 */
	public function getAttributeNode( string $qname ): ?Attr {
		if ( $this->_attributes === null ) {
			return null;
		}
		return $this->_attributes->getNamedItem( $qname );
	}

	/**
	 * Add an Attr node to an Element node
	 *
	 * @inheritDoc
	 */
	public function setAttributeNode( $attr ): ?Attr {
		return $this->getAttributes()->setNamedItem( $attr );
	}

	/**
	 * Remove the given attribute node from this Element
	 *
	 * spec DOM-LS
	 *
	 * @inheritDoc
	 */
	public function removeAttributeNode( $attr ): Attr {
		'@phan-var Attr $attr'; // @var Attr $attr
		$attributes = $this->getAttributes();
		if ( !$attributes->_hasNamedItemNode( $attr ) ) {
			Util::error( "NotFoundError" );
		}
		$attributes->_remove( $attr );
		return $attr;
	}

	/**********************************************************************
	 * ATTRIBUTE NODE NS: get/set
	 */

	/**
	 * Fetch the Attr node with the given namespace and localName
	 *
	 * spec DOM-LS
	 *
	 * @param ?string $ns The attribute's local name
	 * @param string $lname The attribute's local name
	 * @return ?Attr the attribute node, or NULL
	 */
	public function getAttributeNodeNS( ?string $ns, string $lname ): ?Attr {
		if ( $this->_attributes === null ) {
			return null;
		}
		return $this->_attributes->getNamedItemNS( $ns, $lname );
	}

	/**
	 * Add a namespace-aware Attr node to an Element node
	 *
	 * @param IAttr $attr
	 * @return ?Attr
	 */
	public function setAttributeNodeNS( $attr ) {
		'@phan-var Attr $attr'; // @var Attr $attr
		return $this->getAttributes()->setNamedItemNS( $attr );
	}

	/*********************************************************************
	 * OTHER
	 */

	/**
	 * Test whether this Element has any attributes
	 *
	 * spec DOM-LS
	 *
	 * @return bool
	 */
	public function hasAttributes(): bool {
		if ( $this->_attributes === null ) {
			return false;
		}
		return count( $this->_attributes ) > 0;
	}

	/**
	 * Fetch the qualified names of all attributes on this Element
	 *
	 * spec DOM-LS
	 *
	 * NOTE
	 * The names are *not* guaranteed to be unique.
	 *
	 * @return array of strings, or empty array if no attributes.
	 */
	public function getAttributeNames(): array {
		/*
		 * Note that per spec, these are not guaranteed to be
		 * unique.
		 */
		$ret = [];

		foreach ( ( $this->_attributes ?? [] ) as $a ) {
			$ret[] = $a->getName();
		}

		return $ret;
	}

	/**
	 * @return mixed|null
	 */
	public function getClassList() {
		if ( $this->_classList === null ) {
			$this->_classList = new DOMTokenList( $this, 'class' );
		}
		return $this->_classList;
	}

	/**
	 * @param string $selectors
	 * @return bool
	 */
	public function matches( string $selectors ): bool {
		return Zest::matches( $this, $selectors );
	}

	/**
	 * @param string $selectors
	 * @return bool
	 */
	public function webkitMatchesSelector( string $selectors ): bool {
		return $this->matches( $selectors );
	}

	/**
	 * @param string $selectors
	 * @return ?Element
	 */
	public function closest( string $selectors ) {
		$el = $this;
		do {
			if ( $el instanceof Element && $el->matches( $selectors ) ) {
				return $el;
			}
			$el = $el->getParentElement() ?? $el->getParentNode();
		} while ( $el !== null && $el->getNodeType() == Node::ELEMENT_NODE );
		return null;
	}

	/*
	 * DODO EXTENSIONS
	 */

	/**
	 * Calls isHTMLDocument() on ownerDocument
	 * @return bool
	 */
	public function _isHTMLElement(): bool {
		if ( $this->getNamespaceURI() === Util::NAMESPACE_HTML
			 && $this->_nodeDocument->_isHTMLDocument() ) {
			return true;
		}
		return false;
	}

	/**
	 * Return the next element, in source order, after this one or
	 * null if there are no more.  If root element is specified,
	 * then don't traverse beyond its subtree.
	 *
	 * This is not a DOM method, but is convenient for
	 * lazy traversals of the tree.
	 * @param ?Element $root
	 * @return ?Element
	 */
	public function _nextElement( ?Element $root ): ?Element {
		if ( !$root ) {
			$root = $this->_nodeDocument->getDocumentElement();
		}
		$next = $this->getFirstElementChild();
		if ( !$next ) {
			/* don't use sibling if we're at root */
			if ( $this === $root ) {
				return null;
			}
			$next = $this->getNextElementSibling();
		}
		if ( $next ) {
			return $next;
		}

		/*
		 * If we can't go down or across, then we have to go up
		 * and across to the parent sibling or another ancestor's
		 * sibling. Be careful, though: if we reach the root
		 * element, or if we reach the documentElement, then
		 * the traversal ends.
		 */
		for (
			$parent = $this->getParentElement();
			$parent && $parent !== $root;
			$parent = $parent->getParentElement()
		) {
			$next = $parent->getNextElementSibling();
			if ( $next ) {
				// @phan-suppress-next-line PhanTypeMismatchReturn
				return $next;
			}
		}
		return null;
	}

	/**
	 * @param string $lname
	 *
	 * @return HTMLCollection
	 */
	public function getElementsByTagName( string $lname ): HTMLCollection {
		$filter = null;
		if ( !$lname ) {
			return new HTMLCollection();
		}
		if ( $lname === '*' ) {
			$filter = static function ( $el ) {
				return true;
			};
		} elseif ( $this->_nodeDocument->_isHTMLDocument() ) {
			$filter = self::_htmlLocalNameElementFilter( $lname );
		} else {
			$filter = self::_localNameElementFilter( $lname );
		}

		return new FilteredElementList( $this, $filter );
	}

	/**
	 * @param string $names
	 *
	 * @return HTMLCollection
	 */
	public function getElementsByClassName( string $names ) {
		if ( empty( $names ) ) {
			return new HTMLCollection();
		}

		$names = preg_split( '/[ \t\r\n\f]+/',
			$names ); // Split on ASCII whitespace

		return new FilteredElementList(
			$this,
			self::_classNamesElementFilter( $names )
		);
	}

	/**
	 * This is a non-standard Dodo extension that interfaces with the Zest
	 * CSS selector library to allow quick lookup by ID *even if there are
	 * multiple nodes in the document with the same ID*.
	 * @param string $id
	 * @return array<Element>
	 */
	public function _getElementsById( string $id ): array {
		// XXX: We could potentially speed this up by starting with
		// $this->_nodeDocument->_getElementsById($id) and then filtering
		// to include only those with $this as an exclusive ancestor, since
		// we expect only 0 or 1 results from Document::_getElementsById()
		// (only if $this->isConnected though!)
		// @phan-suppress-next-line PhanTypeMismatchReturn
		return iterator_to_array( new FilteredElementList(
			$this,
			static function ( Element $el ) use ( $id ): bool {
				return $el->getAttribute( 'id' ) === $id;
			}
		) );
	}

	/**
	 * @param string $lname
	 *
	 * @return callable(Element):bool
	 */
	private static function _htmlLocalNameElementFilter( string $lname ): callable {
		$lclname = Util::toAsciiLowercase( $lname );
		if ( $lclname === $lname ) {
			return self::_localNameElementFilter( $lname );
		}

		return static function ( $el ) use ( $lname, $lclname ) {
			return $el->_isHTMLElement() ? $el->localName === $lclname : $el->localName === $lname;
		};
	}

	/**
	 * @param string $lname
	 *
	 * @return callable(Element):bool
	 */
	private static function _localNameElementFilter( string $lname ): callable {
		return static function ( $el ) use ( $lname ) {
			return $el->getLocalName() === $lname;
		};
	}

	/**
	 * @param string|null $ns
	 * @param string $lname
	 *
	 * @return HTMLCollection
	 */
	public function getElementsByTagNameNS( ?string $ns, string $lname ): HTMLCollection {
		$filter = null;
		if ( $ns === '' ) {
			$ns = null;
		}
		if ( $ns === '*' && $lname === '*' ) {
			$filter = static function () {
				return true;
			};
		} elseif ( $ns === '*' ) {
			$filter = self::_localNameElementFilter( $lname );
		} elseif ( $lname === '*' ) {
			$filter = self::_namespaceElementFilter( $ns );
		} else {
			$filter = self::_namespaceLocalNameElementFilter( $ns, $lname );
		}

		return new FilteredElementList( $this, $filter );
	}

	/**
	 * @param ?string $ns
	 *
	 * @return callable(Element):bool
	 */
	private static function _namespaceElementFilter( ?string $ns ): callable {
		return static function ( $el ) use ( $ns ) {
			return $el->namespaceURI === $ns;
		};
	}

	/**
	 * @param ?string $ns
	 * @param string $lname
	 *
	 * @return callable(Element):bool
	 */
	private static function _namespaceLocalNameElementFilter( ?string $ns, string $lname ): callable {
		return static function ( $el ) use ( $ns, $lname ) {
			return $el->namespaceURI === $ns && $el->localName === $lname;
		};
	}

	/**
	 * @param array $names
	 *
	 * @return callable(Element):bool
	 */
	private static function _classNamesElementFilter( array $names ): callable {
		return static function ( $el ) use ( $names ) {
			$quirks = $el->_nodeDocument->getCompatMode() === 'BackCompat';
			if ( !$quirks ) {
				foreach ( $names as $name ) {
					if ( $el->getClassList()->contains( $name ) ) {
						return true;
					}
				}
			} else {
				// This is inefficient, but it is rarely used
				foreach ( $names as $c1 ) {
					foreach ( $el->getClassList() as $c2 ) {
						if ( Util::toAsciiLowercase( $c1 ) === Util::toAsciiLowercase( $c2 ) ) {
							return true;
						}
					}
				}
			}
			return false;
		};
	}
}
