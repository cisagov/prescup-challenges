<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Element;
use Wikimedia\Dodo\Node;

/*
 * DOM-LS specifies that in the
 * event that two Elements have
 * the same 'id' attribute value,
 * the first one, in document order,
 * shall be returned from getElementById.
 *
 * This data structure makes that
 * as performant as possible, by:
 *
 * 1. Caching the first element in the list, in document order
 * It is updated on move because a move is treated as a
 * removal followed by an insertion, and those two operations
 * will update this table.
 *
 * 2. Elements are looked up by an integer index set when they
 * are adopted by Document. This index gives a canonical
 * integer representation of an Element, so we can operate
 * on integers instead of Elements.
 */
class MultiId {
	/** @var Element[] */
	public $table = [];

	/** @var int */
	public $length = 0;

	/**
	 * The first element, in document order.
	 *
	 * null indicates the cache is not set and the first element must be re-computed.
	 *
	 * @var ?Element
	 */
	public $first = null;

	/**
	 * @param Element $node
	 */
	public function __construct( Element $node ) {
		$this->table[$node->_documentIndex] = $node;
		$this->length = 1;
		$this->first = null;
	}

	/**
	 * Add an Element to array in O(1) time by using Node::$_documentIndex
	 * as the array index.
	 *
	 * @param Element $node
	 */
	public function add( Element $node ) {
		if ( !isset( $this->table[$node->_documentIndex] ) ) {
			$this->table[$node->_documentIndex] = $node;
			$this->length++;
			$this->first = null; /* invalidate cache */
		}
	}

	/**
	 * Remove an Element from the array in O(1) time by using Node::$_documentIndex
	 * to perform the lookup.
	 *
	 * @param Element $node
	 */
	public function del( Element $node ) {
		if ( $this->table[$node->_documentIndex] ) {
			unset( $this->table[$node->_documentIndex] );
			$this->length--;
			$this->first = null; /* invalidate cache */
		}
	}

	/**
	 * Retrieve that Element from the array which appears first in document order in
	 * the associated document.
	 *
	 * Cache the value for repeated lookups.
	 *
	 * The cache is invalidated each time the array is modified. The list
	 * is modified when a Node is inserted or removed from a Document, or when
	 * the 'id' attribute value of a Node is changed.
	 *
	 * @return ?Element null if there are no nodes
	 */
	public function getFirst() {
		if ( $this->first !== null ) {
			return $this->first;
		}

		// No item has been cached. Well, let's find it then.
		foreach ( $this->table as $index => $node ) {
			if ( $this->first === null ||
				 $this->first->compareDocumentPosition( $node ) & Node::DOCUMENT_POSITION_PRECEDING
			) {
				$this->first = $node;
			}
		}
		return $this->first;
	}

	/**
	 * If there is only one node left, return it. Otherwise return "this".
	 *
	 * @return Element|MultiId
	 */
	public function downgrade() {
		if ( $this->length === 1 ) {
			foreach ( $this->table as $index => $node ) {
				return $node;
			}
		}
		return $this;
	}
}
