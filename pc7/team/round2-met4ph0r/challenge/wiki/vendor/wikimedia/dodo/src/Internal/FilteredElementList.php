<?php

declare( strict_types=1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Element;
use Wikimedia\Dodo\HTMLCollection;

/******************************************************************************
 * FilteredElementList.php
 * -----------
 * This file defines node list implementation that lazily traverses
 * the document tree (or a subtree rooted at any element) and includes
 * only those elements for which a specified filter function returns true.
 * It is used to implement the
 * {Document,Element}.getElementsBy{TagName,ClassName}{,NS} methods.
 */
class FilteredElementList extends HTMLCollection {
	use UnimplementedTrait;

	/**
	 * @var array<Element>
	 */
	public $cache;
	/**
	 * @var callable(Element):bool
	 */
	private $filter;
	/**
	 * @var Element
	 */
	private $root;
	/**
	 * @var int
	 */
	private $lastModTime;
	/**
	 * @var bool
	 */
	private $done;

	/**
	 * FilteredElementList constructor.
	 *
	 * @param Element $root
	 * @param callable(Element):bool $filter
	 */
	public function __construct( $root, callable $filter ) {
		parent::__construct();
		$this->root = $root;
		$this->filter = $filter;
		$this->lastModTime = $root->_lastModTime();
		$this->done = false;
		$this->cache = [];
		$this->_traverse();
	}

	/**
	 * If n is specified, then traverse the tree until we've found the nth
	 * item (or until we've found all items).  If n is not specified,
	 * traverse until we've found all items.
	 *
	 * @param int|null $n
	 */
	public function _traverse( int $n = null ) {
		if ( $n !== null ) {
			$n++;
		}

		$start = $this->root;
		$elt = $this->_next( $start );
		while ( $elt !== null ) {
			$this->cache[] = $elt;
			if ( $n && count( $this->cache ) === $n ) {
				return;
			}
			$elt = $this->_next( $elt );
		}

		// no next element, so we've found everything
		$this->done = true;
	}

	/**
	 * @param Element $start
	 *
	 * @return Element|null
	 */
	private function _next( Element $start ): ?Element {
		$elt = $start->_nextElement( $this->root );

		while ( $elt ) {
			if ( ( $this->filter )( $elt ) ) {
				return $elt;
			}

			$elt = $elt->_nextElement( $this->root );
		}

		return null;
	}

	/**
	 * @return int
	 */
	public function getLength(): int {
		$this->checkcache();
		if ( !$this->done ) {
			$this->_traverse();
		}

		return count( $this->cache );
	}

	/**
	 *
	 */
	private function checkcache() {
		if ( $this->lastModTime !== $this->root->_lastModTime() ) {
			$this->cache = [];
			$this->done = false;
			$this->lastModTime = $this->root->_lastModTime();
		}
	}

	/**
	 * @param int $n
	 *
	 * @return Element|null
	 */
	public function item( int $n ): ?Element {
		$this->checkcache();
		if ( !$this->done && $n >= count( $this->cache ) ) {
			// This can lead to O(N^2) behavior if we stop when we get to n
			// and the caller is iterating through the items in order; so
			// be sure to do the full traverse here.
			$this->_traverse();
		}

		return $this->cache[$n] ?? null;
	}

	/** @inheritDoc */
	public function namedItem( string $name ): ?Element {
		// @phan-suppress-previous-line PhanPluginNeverReturnMethod
		throw $this->_unimplemented();
	}
}
