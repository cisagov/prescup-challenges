<?php

declare( strict_types = 1 );
// phpcs:disable PSR2.Classes.PropertyDeclaration.Underscore

namespace Wikimedia\Dodo;

/**
 * NodeList.php
 *
 * @phan-forbid-undeclared-magic-properties
 */
/* Played fairly straight. Used for Node::childNodes when in "array mode". */
class NodeList implements \Wikimedia\IDLeDOM\NodeList {
	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\NodeList;

	/**
	 * @var Node[] Backing storage for the NodeList
	 */
	private $_list = [];

	/** Create a new empty NodeList */
	public function __construct() {
	}

	/** @inheritDoc */
	public function item( int $i ): ?Node {
		return $this->_list[$i] ?? null;
	}

	/** @inheritDoc */
	public function getLength(): int {
		return count( $this->_list );
	}

	/**
	 * For internal use only: append a node to the backing array.
	 * @param Node $n
	 */
	public function _append( Node $n ): void {
		$this->_list[] = $n;
	}

	/**
	 * For internal use only: replace the node at the given index.
	 * @param int $index
	 * @param Node $n
	 */
	public function _set( int $index, Node $n ): void {
		$this->_list[$index] = $n;
	}

	/**
	 * For internal use only: splice nodes in the backing array.
	 * @param int $offset
	 * @param int $length
	 * @param Node[] $replacement
	 */
	public function _splice( int $offset, int $length, array $replacement = [] ): void {
		array_splice( $this->_list, $offset, $length, $replacement );
	}
}
