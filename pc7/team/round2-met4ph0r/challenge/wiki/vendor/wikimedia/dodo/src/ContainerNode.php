<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\WhatWG;

/**
 * The ContainerNode class defines common functionality for node subtypes
 * that can have children.  We factor this out so that leaf nodes can
 * save the space required to maintain the list of children.  There are
 * a lot of leaf nodes in a document, so this space can add up.
 *
 * The list of children is kept primarily as a circular linked list of
 * siblings.  We fail over to an array of children (which makes
 * insertion and removal much more expensive) only when required.
 */
abstract class ContainerNode extends Node {
	/**
	 * @var ?Node The first child, if we're using the linked list representation
	 */
	public $_firstChild;

	/**
	 * @var ?NodeList An array of children, or null to indicate we're using
	 *   the linked list representation.
	 */
	public $_childNodes;

	/**
	 * @param Document $nodeDocument
	 */
	public function __construct( Document $nodeDocument ) {
		parent::__construct( $nodeDocument );
		/* Our children */
		$this->_firstChild = null;
		$this->_childNodes = null;
	}

	/**
	 * Return true iff there are children of this node.
	 *
	 * Note that we must test `_childNodes` to determine which representation
	 * to consult.
	 *
	 * @inheritDoc
	 */
	public function hasChildNodes(): bool {
		if ( $this->_childNodes === null ) {
			// We're using the linked list representation.
			return $this->_firstChild !== null;
		} else {
			// We're using the NodeList representation
			return $this->_childNodes->getLength() > 0;
		}
	}

	/** @inheritDoc */
	public function _length(): int {
		return $this->getChildNodes()->getLength();
	}

	/** @inheritDoc */
	public function _empty(): bool {
		return !$this->hasChildNodes();
	}

	/**
	 * Keeping child nodes as an array makes insertion/removal of nodes
	 * quite expensive.  So we try *never* to create this array, if
	 * possible, keeping `$this->childNodes` set to null.  If someone
	 * actually fetches the childNodes list we lazily create it.
	 * It then has to be live, and so we must update it whenever
	 * nodes are appended or removed.
	 *
	 * @inheritDoc
	 */
	public function getChildNodes(): NodeList {
		if ( $this->_childNodes === null ) {
			// If childNodes has never been created, we've now created it.
			$this->_childNodes = new NodeList();
			// optimized circular linked list traversal
			$childNodes = new NodeList();
			$first = $this->_firstChild;
			$kid = $first;
			if ( $kid !== null ) {
				do {
					$childNodes->_append( $kid );
					$kid = $kid->_nextSibling;
				} while ( $kid !== $first ); // circular linked list
			}
			$this->_childNodes = $childNodes;
			// The first child could later be removed, but we'd still be
			// holding on to a reference.  So set _firstChild to null to
			// allow freeing up that memory.
			$this->_firstChild = null;
		}
		return $this->_childNodes;
	}

	/**
	 * Be careful to use this method in most cases rather than directly
	 * access `_firstChild`.
	 *
	 * @inheritDoc
	 */
	public function getFirstChild(): ?Node {
		$kids = $this->_childNodes;
		if ( $kids === null ) {
			/*
			 * If we are using the Linked List representation, then just return
			 * the backing property (may still be null).
			 */
			return $this->_firstChild;
		}
		$len = $kids->getLength();
		return $len === 0 ? null : $kids->item( 0 );
	}

	/**
	 * @inheritDoc
	 */
	public function getLastChild(): ?Node {
		$kids = $this->_childNodes;
		if ( $kids !== null ) {
			// We are using the NodeList representation.
			$len = $kids->getLength();
			return $len === 0 ? null : $kids->item( $len - 1 );
		}
		// We are using the Linked List representation.
		if ( $this->_firstChild === null ) {
			return null;
		}
		// If we have a firstChild, its _previousSibling is the last child,
		// because this is a circularly linked list.
		return $this->_firstChild->_previousSibling;
	}

	// These next methods are defined on Element and DocumentFragment with
	// identical behavior.  Note that they are defined differently on Document,
	// however, so we need to override this definition in that class.

	/**
	 * Generic implementation of ::getTextContent to be used by Element
	 * and DocumentFragment (but not Document!).
	 * @see https://dom.spec.whatwg.org/#dom-node-textcontent
	 * @return ?string
	 */
	public function getTextContent(): ?string {
		$text = [];
		WhatWG::descendantTextContent( $this, $text );
		return implode( "", $text );
	}

	/**
	 * Generic implementation of ::setTextContent to be used by Element
	 * and DocumentFragment (but not Document!).
	 * @see https://dom.spec.whatwg.org/#dom-node-textcontent
	 * @param ?string $value
	 */
	public function setTextContent( ?string $value ): void {
		$value = $value ?? '';
		$this->_removeChildren();
		if ( $value !== "" ) {
			/* Equivalent to Node:: appendChild without checks! */
			$this->_unsafeAppendChild(
				$this->_nodeDocument->createTextNode( $value )
			);
		}
	}

}
