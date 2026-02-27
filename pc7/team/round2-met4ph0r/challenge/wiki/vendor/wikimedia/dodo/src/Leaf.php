<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\Util;

/*
 * This trait selectively overrides Node, providing an alternative
 * (more performant) base class for Node subclasses that can never
 * have children, such as those derived from the abstract CharacterData
 * class.
 */
abstract class Leaf /* domino helper */ extends Node {

	/**
	 * @inheritDoc
	 */
	final public function hasChildNodes(): bool {
		return false;
	}

	/**
	 * @inheritDoc
	 */
	final public function getFirstChild(): ?Node {
		return null;
	}

	/**
	 * @inheritDoc
	 */
	final public function getLastChild(): ?Node {
		return null;
	}

	/**
	 * @inheritDoc
	 */
	final public function insertBefore( $node, $refChild = null ): Node {
		Util::error( "HierarchyRequestError" );
	}

	/**
	 * @inheritDoc
	 */
	final public function replaceChild( $node, $refChild ): Node {
		Util::error( "HierarchyRequestError" );
	}

	/**
	 * @inheritDoc
	 */
	final public function removeChild( $node ): Node {
		Util::error( "NotFoundError" );
	}

	/**
	 * @inheritDoc
	 */
	final public function _removeChildren(): void {
		/* no-op */
	}

	/**
	 * @inheritDoc
	 */
	final public function getChildNodes(): NodeList {
		// Possibly not entirely spec-compliant, but we don't want to
		// allocate an extra property in every leaf node *just in case*.
		// If object identity is important, we could change this to
		// NodeList::emptySingleton() or something like that.
		return new NodeList();
	}
}
