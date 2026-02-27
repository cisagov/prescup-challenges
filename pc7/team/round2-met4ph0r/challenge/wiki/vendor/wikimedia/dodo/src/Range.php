<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BoundaryPoint;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;
use Wikimedia\IDLeDOM\Node as INode;

/**
 * A live range.
 * @see https://dom.spec.whatwg.org/#concept-live-range
 */
class Range extends AbstractRange implements \Wikimedia\IDLeDOM\Range {

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\Range;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Range;

	/**
	 * Constructor, used by Document::createRange()
	 * @see https://dom.spec.whatwg.org/#dom-document-createrange
	 * @param Document $doc The document associated with this Range
	 */
	public function __construct( Document $doc ) {
		parent::__construct( $doc, 0, $doc, 0 );
	}

	/**
	 * @return Node
	 */
	public function getCommonAncestorContainer() {
		$endNode = $this->getEndContainer();
		$endAncestors = [];
		while ( $endNode !== null ) {
			$endAncestors[] = $endNode;
			$endNode = $endNode->getParentNode();
		}
		$container = $this->getStartContainer();
		while ( !in_array( $container, $endAncestors, true ) ) {
			$container = $container->getParentNode();
		}
		'@phan-var Node $container'; // @var Node $container
		return $container;
	}

	/**
	 * @param INode $node
	 * @param int $offset
	 */
	public function setStart( $node, int $offset ): void {
		'@phan-var Node $node'; // @var Node $node
		if ( $node instanceof \Wikimedia\IDLeDOM\DocumentType ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		if ( $offset > $node->_length() ) {
			Util::error( 'IndexSizeError' );
		}
		$bp = new BoundaryPoint( $node, $offset );
		if (
			$this->_root() !== self::_nodeRoot( $node ) ||
			$bp->compare( $this->_end ) > 0
		) {
			$this->_end = $bp;
		}
		$this->_start = $bp;
	}

	/**
	 * @param INode $node
	 * @param int $offset
	 */
	public function setEnd( $node, int $offset ): void {
		'@phan-var Node $node'; // @var Node $node
		if ( $node instanceof \Wikimedia\IDLeDOM\DocumentType ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		if ( $offset > $node->_length() ) {
			Util::error( 'IndexSizeError' );
		}
		$bp = new BoundaryPoint( $node, $offset );
		if (
			$this->_root() !== self::_nodeRoot( $node ) ||
			$bp->compare( $this->_start ) < 0
		) {
			$this->_start = $bp;
		}
		$this->_end = $bp;
	}

	/**
	 * Return the root of this range.
	 * @see https://dom.spec.whatwg.org/#concept-range-root
	 * @return Node
	 */
	private function _root(): Node {
		return self::_nodeRoot( $this->getStartContainer() );
	}

	/**
	 * Return the root of a node.
	 * @see https://dom.spec.whatwg.org/#concept-tree-root
	 * @param Node $n the node
	 * @return Node
	 */
	private static function _nodeRoot( Node $n ): Node {
		while ( true ) {
			$parent = $n->getParentNode();
			if ( $parent === null ) {
				break;
			}
			$n = $parent;
		}
		return $n;
	}

	/**
	 * @param INode $node
	 */
	public function setStartBefore( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$this->setStart( $parent, $node->_getSiblingIndex() );
	}

	/**
	 * @param INode $node
	 */
	public function setStartAfter( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$this->setStart( $parent, $node->_getSiblingIndex() + 1 );
	}

	/**
	 * @param INode $node
	 */
	public function setEndBefore( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$this->setEnd( $parent, $node->_getSiblingIndex() );
	}

	/**
	 * @param INode $node
	 */
	public function setEndAfter( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$this->setEnd( $parent, $node->_getSiblingIndex() + 1 );
	}

	/**
	 * @param bool $toStart
	 */
	public function collapse( bool $toStart = false ): void {
		if ( $toStart ) {
			$this->_end = $this->_start;
		} else {
			$this->_start = $this->_end;
		}
	}

	/**
	 * @param INode $node
	 */
	public function selectNode( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$index = $node->_getSiblingIndex();
		$this->_start = new BoundaryPoint( $parent, $index );
		$this->_end = new BoundaryPoint( $parent, $index + 1 );
	}

	/**
	 * @param INode $node
	 */
	public function selectNodeContents( $node ): void {
		'@phan-var Node $node'; // @var Node $node
		if ( $node instanceof \Wikimedia\IDLeDOM\DocumentType ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$length = $node->_length();
		$this->_start = new BoundaryPoint( $node, 0 );
		$this->_end = new BoundaryPoint( $node, $length );
	}

	/**
	 * @param int $how
	 * @param \Wikimedia\IDLeDOM\Range $sourceRange
	 *
	 * @return int
	 */
	public function compareBoundaryPoints( int $how, $sourceRange ): int {
		'@phan-var Range $sourceRange'; // @var Range $sourceRange
		$thisPoint = null;
		$otherPoint = null;
		switch ( $how ) {
		case self::START_TO_START:
		case self::END_TO_START:
			$thisPoint = $this->_start;
			break;
		case self::START_TO_END:
		case self::END_TO_END:
			$thisPoint = $this->_end;
			break;
		default:
			Util::error( 'NotSupportedError' );
		}
		if ( $this->_root() !== $sourceRange->_root() ) {
			Util::error( 'WrongDocumentError' );
		}
		switch ( $how ) {
		case self::START_TO_START:
		case self::START_TO_END:
			$otherPoint = $sourceRange->_start;
			break;
		case self::END_TO_END:
		case self::END_TO_START:
			$otherPoint = $sourceRange->_end;
			break;
		default:
			Util::error( 'NotSupportedError' );
		}
		return $thisPoint->compare( $otherPoint );
	}

	/**
	 * Return a new live range with the same start and end as this.
	 * @see https://dom.spec.whatwg.org/#dom-range-clonerange
	 * @return Range
	 */
	public function cloneRange(): Range {
		$doc = $this->getStartContainer()->_nodeDocument;
		$r = $doc->createRange();
		$r->setStart( $this->getStartContainer(), $this->getStartOffset() );
		$r->setEnd( $this->getEndContainer(), $this->getEndOffset() );
		return $r;
	}

	/**
	 * @inheritDoc
	 */
	public function detach(): void {
		/* do nothing */
	}

	/**
	 * @param INode $node
	 * @param int $offset
	 *
	 * @return bool
	 */
	public function isPointInRange( $node, int $offset ): bool {
		'@phan-var Node $node'; // @var Node $node
		if ( self::_nodeRoot( $node ) !== $this->_root() ) {
			return false;
		}
		if ( $node instanceof \Wikimedia\IDLeDOM\DocumentType ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		if ( $offset > $node->_length() ) {
			Util::error( 'IndexSizeError' );
		}
		$bp = new BoundaryPoint( $node, $offset );
		if ( $bp->compare( $this->_start ) < 0 ) {
			return false; // (node,offset) is before start
		}
		if ( $bp->compare( $this->_end ) > 0 ) {
			return false; // (node, offset) is after end
		}
		return true;
	}

	/**
	 * @param INode $node
	 * @param int $offset
	 *
	 * @return int
	 */
	public function comparePoint( $node, int $offset ): int {
		'@phan-var Node $node'; // @var Node $node
		if ( self::_nodeRoot( $node ) !== $this->_root() ) {
			Util::error( 'WrongDocumentError' );
		}
		if ( $node instanceof \Wikimedia\IDLeDOM\DocumentType ) {
			Util::error( 'InvalidNodeTypeError' );
		}
		if ( $offset > $node->_length() ) {
			Util::error( 'IndexSizeError' );
		}
		$bp = new BoundaryPoint( $node, $offset );
		if ( $bp->compare( $this->_start ) < 0 ) {
			return -1; // (node,offset) is before start
		}
		if ( $bp->compare( $this->_end ) > 0 ) {
			return +1; // (node, offset) is after end
		}
		return 0;
	}

	/**
	 * @param INode $node
	 *
	 * @return bool
	 */
	public function intersectsNode( $node ): bool {
		'@phan-var Node $node'; // @var Node $node
		if ( self::_nodeRoot( $node ) !== $this->_root() ) {
			return false;
		}
		$parent = $node->getParentNode();
		if ( $parent === null ) {
			return true;
		}
		$offset = $node->_getSiblingIndex();
		$bp1 = new BoundaryPoint( $parent, $offset );
		$bp2 = new BoundaryPoint( $parent, $offset + 1 );
		if ( $bp1->compare( $this->_end ) < 0 && $bp2->compare( $this->_start ) > 0 ) {
			return true;
		}
		return false;
	}

	/**
	 * @return string
	 */
	public function toString(): string {
		return $this->extractContents()->getTextContent() ?? '';
	}
}
