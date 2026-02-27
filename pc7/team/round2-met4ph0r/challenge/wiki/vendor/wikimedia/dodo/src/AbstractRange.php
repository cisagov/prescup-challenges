<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BoundaryPoint;

/**
 * An abstract range.
 * @see https://dom.spec.whatwg.org/#concept-range
 * @phan-forbid-undeclared-magic-properties
 */
class AbstractRange implements \Wikimedia\IDLeDOM\AbstractRange {

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\AbstractRange;

	/**
	 * @var BoundaryPoint
	 */
	protected $_start;

	/**
	 * @var BoundaryPoint
	 */
	protected $_end;

	/**
	 * Create a new AbstractRange object. For subclass use only.
	 * @param Node $startContainer
	 * @param int $startOffset
	 * @param Node $endContainer
	 * @param int $endOffset
	 */
	protected function __construct(
		Node $startContainer, int $startOffset,
		Node $endContainer, int $endOffset
	) {
		$this->_start = new BoundaryPoint( $startContainer, $startOffset );
		$this->_end = new BoundaryPoint( $endContainer, $endOffset );
	}

	/**
	 * @return Node
	 */
	public function getStartContainer() {
		return $this->_start->getNode();
	}

	/**
	 * @return int
	 */
	public function getStartOffset(): int {
		return $this->_start->getOffset();
	}

	/**
	 * @return Node
	 */
	public function getEndContainer() {
		return $this->_end->getNode();
	}

	/**
	 * @return int
	 */
	public function getEndOffset(): int {
		return $this->_end->getOffset();
	}

	/**
	 * @return bool
	 */
	public function getCollapsed(): bool {
		return $this->_start->equals( $this->_end );
	}
}
