<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\NodeTraversal;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;

/**
 * NodeIterator
 *
 * Implemented version: http://www.w3.org/TR/2015/WD-dom-20150618/#nodeiterator
 *
 * Latest version: http://www.w3.org/TR/dom/#nodeiterator
 * @phan-forbid-undeclared-magic-properties
 */
class NodeIterator implements \Wikimedia\IDLeDOM\NodeIterator {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\NodeIterator;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\NodeIterator;

	/** @var Node */
	private $_root;
	/** @var Node */
	private $_referenceNode;
	/** @var bool */
	private $_pointerBeforeReferenceNode;
	/** @var int */
	private $_whatToShow;
	/** @var ?NodeFilter */
	private $_filter;
	/** @var bool */
	private $_active;

	/**
	 * Internal use only: use Document#createNodeIterator()
	 * @param Node $root
	 * @param int $whatToShow
	 * @param callable|NodeFilter|null $filter
	 */
	public function __construct( Node $root, int $whatToShow, $filter ) {
		$this->_root = $root;
		$this->_referenceNode = $root;
		$this->_pointerBeforeReferenceNode = true;
		$this->_whatToShow = $whatToShow;
		$this->_filter = $filter === null ? null : NodeFilter::cast( $filter );
		$this->_active = false;
		// Record active node iterators in the document, in order to perform
		// "node iterator pre-removal steps"
		$root->_nodeDocument->_attachNodeIterator( $this );
	}

	/**
	 * @return Node
	 */
	public function getRoot() {
		return $this->_root;
	}

	/**
	 * @return Node
	 */
	public function getReferenceNode() {
		return $this->_referenceNode;
	}

	/**
	 * @return bool
	 */
	public function getPointerBeforeReferenceNode(): bool {
		return $this->_pointerBeforeReferenceNode;
	}

	/**
	 * @return int
	 */
	public function getWhatToShow(): int {
		return $this->_whatToShow;
	}

	/**
	 * @return ?NodeFilter
	 */
	public function getFilter(): ?NodeFilter {
		return $this->_filter;
	}

	/**
	 * Internal filter function, using the given filter as well as
	 * `whatToShow`.
	 * @param Node $node
	 * @return int NodeFilter::FILTER_ACCEPT, NodeFilter::FILTER_REJECT, or
	 *   NodeFilter::FILTER_SKIP
	 */
	private function _internalFilter( Node $node ): int {
		if ( $this->_active ) {
			Util::error( 'InvalidStateError' );
		}
		// Maps nodeType to whatToShow
		if ( !( ( ( 1 << ( $node->getNodeType() - 1 ) ) & $this->_whatToShow ) ) ) {
			return NodeFilter::FILTER_SKIP;
		}

		$filter = $this->_filter;
		if ( $filter === null ) {
			return NodeFilter::FILTER_ACCEPT;
		}
		$this->_active = true; // Prevent reentrance
		try {
			return $filter->acceptNode( $node );
		} finally {
			$this->_active = false;
		}
	}

	/**
	 * @spec https://dom.spec.whatwg.org/#nodeiterator-pre-removing-steps
	 * @param Node $toBeRemovedNode the Node about to be removed
	 * @return void
	 */
	public function _preremove( Node $toBeRemovedNode ): void {
		if ( self::_isInclusiveAncestor( $toBeRemovedNode, $this->_root ) ) {
			return;
		}
		if ( !self::_isInclusiveAncestor( $toBeRemovedNode, $this->_referenceNode ) ) {
			return;
		}
		if ( $this->_pointerBeforeReferenceNode ) {
			$next = $toBeRemovedNode;
			while ( true ) {
				$lastChild = $next->getLastChild();
				if ( $lastChild === null ) {
					break;
				}
				$next = $lastChild;
			}
			$next = NodeTraversal::next( $next, $this->_root );
			if ( $next !== null ) {
				$this->_referenceNode = $next;
				return;
			}
			$this->_pointerBeforeReferenceNode = false;
			// fall through
		}
		$prevSibling = $toBeRemovedNode->getPreviousSibling();
		if ( $prevSibling === null ) {
			// @phan-suppress-next-line PhanPossiblyNullTypeMismatchProperty
			$this->_referenceNode = $toBeRemovedNode->getParentNode();
		} else {
			$this->_referenceNode = $prevSibling;
			for ( $lastChild = $this->_referenceNode->getLastChild();
				 $lastChild !== null;
				 $lastChild = $this->_referenceNode->getLastChild() ) {
				$this->_referenceNode = $lastChild;
			}
		}
	}

	/**
	 * @spec http://www.w3.org/TR/dom/#dom-nodeiterator-nextnode
	 * @return ?Node|null
	 */
	public function nextNode(): ?Node {
		return $this->_traverse( true );
	}

	/**
	 * @spec http://www.w3.org/TR/dom/#dom-nodeiterator-previousnode
	 * @return ?Node
	 */
	public function previousNode(): ?Node {
		return $this->_traverse( false );
	}

	/**
	 * @spec http://www.w3.org/TR/dom/#dom-nodeiterator-detach
	 * @return void
	 */
	public function detach(): void {
		/* "The detach() method must do nothing.
		* Its functionality (disabling a NodeIterator object) was removed,
		* but the method itself is preserved for compatibility.
		*/
	}

	/** @return string */
	public function toString(): string {
		// For compatibility with web-platform-tests
		return '[object NodeIterator]';
	}

	// Private helpers

	/**
	 * @based on WebKit's NodeIterator::moveToNext and NodeIterator::moveToPrevious
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeIterator.cpp?rev=186279#L51
	 * @param Node $node
	 * @param Node $stayWithin
	 * @param bool $directionIsNext
	 * @return ?Node
	 */
	private static function _move( Node $node, Node $stayWithin, bool $directionIsNext ): ?Node {
		if ( $directionIsNext ) {
			return NodeTraversal::next( $node, $stayWithin );
		} else {
			if ( $node === $stayWithin ) {
				return null;
			}
			return NodeTraversal::previous( $node, null );
		}
	}

	/**
	 * Walk the ancestors of $possibleChild looking for $node.
	 * @param Node $node
	 * @param Node $possibleChild
	 * @return bool
	 */
	private static function _isInclusiveAncestor( Node $node, Node $possibleChild ) {
		for ( ; $possibleChild !== null; $possibleChild = $possibleChild->getParentNode() ) {
			if ( $node === $possibleChild ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @spec http://www.w3.org/TR/dom/#concept-nodeiterator-traverse
	 * @param bool $directionIsNext
	 * @return ?Node
	 */
	private function _traverse( bool $directionIsNext ) {
		$node = $this->_referenceNode;
		$beforeNode = $this->_pointerBeforeReferenceNode;
		while ( true ) {
			if ( $beforeNode === $directionIsNext ) {
				$beforeNode = !$beforeNode;
			} else {
				$node = self::_move( $node, $this->_root, $directionIsNext );
				if ( $node === null ) {
					return null;
				}
			}
			$result = $this->_internalFilter( $node );
			if ( $result === NodeFilter::FILTER_ACCEPT ) {
				break;
			}
		}
		$this->_referenceNode = $node;
		$this->_pointerBeforeReferenceNode = $beforeNode;
		return $node;
	}

}
