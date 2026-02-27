<?php

declare( strict_types = 1 );
// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.ScopeNotCamelCaps

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Node;

/******************************************************************************
 * linked_list.php
 * ---------------
 *
 * Methods to operate on nodes of a circular linked list, where the
 * nodes are linked by references called _previousSibling and _nextSibling.
 *
 * That means our Node object is a node in a linked list! Yes, in reality
 * this is just rather tightly coupled to Node.
 */
class LinkedList {
	/**
	 * Determine if the object we want to treat as a (circular) linked list
	 * has the necessary data elements and that the elements aren't null.
	 *
	 * @param Node $a "circular ll node"
	 */
	private static function assertLLIsValid( $a ) {
		Util::assert( $a !== null, "list is falsy" );
		Util::assert( $a->_previousSibling !== null, "previous is falsy" );
		Util::assert( $a->_nextSibling !== null, "next is falsy" );

		/* TODO: Check that list is actually circular? */
	}

	/**
	 * Insert $a before $b
	 *
	 * @param Node $a "circular ll node" (THING TO BE INSERTED BEFORE $b)
	 * @param Node $b "circular ll node" (THING BEFORE WHICH WE INSERT $a)
	 * @return void
	 *
	 * NOTE
	 * Given what this is actually doing (if you draw it out), this could
	 * probably be renamed to 'link', where we are linking $a to $b.
	 */
	public static function ll_insert_before( $a, $b ) {
		self::assertLLIsValid( $a );
		self::assertLLIsValid( $b );

		$a_first = $a;
		$a_last  = $a->_previousSibling;
		$b_first = $b;
		$b_last  = $b->_previousSibling;

		$a_first->_previousSibling = $b_last;
		$a_last->_nextSibling      = $b_first;
		$b_last->_nextSibling      = $a_first;
		$b_first->_previousSibling = $a_last;

		self::assertLLIsValid( $a );
		self::assertLLIsValid( $b );
	}

	/**
	 * Remove a single node $a from its list
	 *
	 * @param Node $a "circular ll node" to be removed
	 * @return void
	 *
	 * NOTE
	 * Again, given what this is doing, could probably re-name
	 * to 'unlink'.
	 */
	public static function ll_remove( $a ) {
		self::assertLLIsValid( $a );

		$prev = $a->_previousSibling;

		if ( $prev === $a ) {
			return;
		}

		$next = $a->_nextSibling;
		$prev->_nextSibling = $next;
		$next->_previousSibling = $prev;
		$a->_previousSibling = $a->_nextSibling = $a;

		self::assertLLIsValid( $a );
	}

	/**
	 * Replace a single node $a with a list $b (which could be null)
	 *
	 * @param Node $a "circular ll node"
	 * @param ?Node $b "circular ll node" (or null)
	 * @return void
	 *
	 * NOTE
	 * I don't like this method. It's confusing.
	 */
	public static function ll_replace( $a, $b ) {
		self::assertLLIsValid( $a );
		if ( $b !== null ) {
			self::assertLLIsValid( $b );
			self::ll_insert_before( $b, $a );
		}
		self::ll_remove( $a );

		self::assertLLIsValid( $a );
		if ( $b !== null ) {
			self::assertLLIsValid( $b );
		}
	}
}
