<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Node;

/**
 * NodeTraversal
 */
abstract class NodeTraversal {
	/**
	 * Based on WebKit's NodeTraversal::nextSkippingChildren
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeTraversal.h?rev=179143#L109
	 * @param Node $node
	 * @param ?Node $stayWithin
	 * @return ?Node
	 */
	public static function nextSkippingChildren( Node $node, ?Node $stayWithin ): ?Node {
		if ( $node === $stayWithin ) {
			return null;
		}
		$nextSibling = $node->getNextSibling();
		if ( $nextSibling !== null ) {
			return $nextSibling;
		}
		return self::nextAncestorSibling( $node, $stayWithin );
	}

	/**
	 * Based on WebKit's NodeTraversal::nextAncestorSibling
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeTraversal.cpp?rev=179143#L93
	 * @param Node $node
	 * @param ?Node $stayWithin
	 * @return ?Node
	 */
	public static function nextAncestorSibling( Node $node, ?Node $stayWithin ): ?Node {
		for ( $node = $node->getParentNode(); $node !== null; $node = $node->getParentNode() ) {
			if ( $node === $stayWithin ) {
				return null;
			}
			$nextSibling = $node->getNextSibling();
			if ( $nextSibling !== null ) {
				return $nextSibling;
			}
		}
		return null;
	}

	/**
	 * Based on WebKit's NodeTraversal::next
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeTraversal.h?rev=179143#L99
	 * @param Node $node
	 * @param ?Node $stayWithin
	 * @return ?Node
	 */
	public static function next( Node $node, ?Node $stayWithin ): ?Node {
		$n = $node->getFirstChild();
		if ( $n !== null ) {
			return $n;
		}
		if ( $node === $stayWithin ) {
			return null;
		}
		$n = $node->getNextSibling();
		if ( $n !== null ) {
			return $n;
		}
		return self::nextAncestorSibling( $node, $stayWithin );
	}

	/**
	 * Based on WebKit's NodeTraversal::deepLastChild
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeTraversal.cpp?rev=179143#L116
	 * @param Node $node
	 * @return ?Node
	 */
	public static function deepLastChild( Node $node ): ?Node {
		while ( $node->getLastChild() !== null ) {
			$node = $node->getLastChild();
		}
		return $node;
	}

	/**
	 * Based on WebKit's NodeTraversal::previous
	 * https://trac.webkit.org/browser/trunk/Source/WebCore/dom/NodeTraversal.h?rev=179143#L121
	 * @param Node $node
	 * @param ?Node $stayWithin
	 * @return ?Node
	 */
	public static function previous( Node $node, ?Node $stayWithin ): ?Node {
		$p = $node->getPreviousSibling();
		if ( $p !== null ) {
			return self::deepLastChild( $p );
		}
		$p = $node->getParentNode();
		if ( $p === $stayWithin ) {
			return null;
		}
		return $p;
	}
}
