<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Node as Node;

/**
 * A boundary point is a concept defined in the DOM spec but never given
 * a formal WebIDL interface.  It is a combination of a node and an offset.
 * @see https://dom.spec.whatwg.org/#concept-range-bp
 */
class BoundaryPoint {
	/** @var Node */
	private $_node;
	/** @var int */
	private $_offset;

	/**
	 * Create a new BoundaryPoint from a Node and a non-negative offset.
	 * @param Node $node
	 * @param int $offset a non-negative offset
	 */
	public function __construct( Node $node, int $offset ) {
		Util::assert( $offset >= 0, "Offset should be non-negative" );
		$this->_node = $node;
		$this->_offset = $offset; // XXX should be non-negative
	}

	/**
	 * @return Node this boundary point's node.
	 */
	public function getNode(): Node {
		return $this->_node;
	}

	/**
	 * @return int this boundary point's offset.
	 */
	public function getOffset(): int {
		return $this->_offset;
	}

	/**
	 * @param BoundaryPoint $bp
	 * @return bool true iff $this is the same boundary point as $bp
	 */
	public function equals( BoundaryPoint $bp ): bool {
		return (
			$this->getNode() === $bp->getNode() &&
			$this->getOffset() === $bp->getOffset()
		);
	}

	/**
	 * @see https://dom.spec.whatwg.org/#concept-range-bp-position
	 * @param BoundaryPoint $bp
	 * @return int -1 if $this is before $bp, 0 if they are equal, or 1 if this
	 *   is after $bp.
	 */
	public function compare( BoundaryPoint $bp ): int {
		// XXX assert that $this->getNode() and $bp->getNode() have the same
		// root.
		$nodeA = $this->getNode();
		$nodeB = $bp->getNode();
		$offsetA = $this->getOffset();
		$offsetB = $bp->getOffset();
		if ( $nodeA === $nodeB ) {
			if ( $offsetA === $offsetB ) {
				return 0;
			}
			if ( $offsetA < $offsetB ) {
				return -1;
			}
			return +1;
		}
		// Argument order is unexpected here.  '$c' will tell us the
		// position of *nodeA* compared to *nodeB*.  That is,
		// "following" mean nodeA is *after* nodeB, and "contains"
		// means nodeA is an ancestor of nodeB (it's tempting to read
		// the arguments in the opposite order; and indeed this
		// BoundaryPoint::compare method has the arguments in the
		// opposite order)
		$c = $nodeB->compareDocumentPosition( $nodeA );
		if ( ( $c & Node::DOCUMENT_POSITION_FOLLOWING ) !== 0 ) {
			return -( $bp->compare( $this ) );
		}
		if ( ( $c & Node::DOCUMENT_POSITION_CONTAINS ) !== 0 ) {
			$child = $nodeB;
			while ( true ) {
				$parent = $child->getParentNode();
				if ( $parent === $nodeA ) {
					break;
				}
				$child = $parent;
			}
			if ( $child->_getSiblingIndex() < $offsetA ) {
				return 1; // after
			}
		}
		return -1; // before
	}
}
