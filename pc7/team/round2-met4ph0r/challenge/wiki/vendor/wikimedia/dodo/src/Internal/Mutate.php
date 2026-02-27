<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

/**
 * Internal constants for implementation-specific mutation handlers.
 */
interface Mutate {
	/** The value of a Text, Comment or PI node changed */
	public const VALUE = 1;
	/** A new attribute was added or an attribute value and/or prefix changed */
	public const ATTR = 2;
	/** An attribute was removed */
	public const REMOVE_ATTR = 3;
	/** A node was removed */
	public const REMOVE = 4;
	/** A node was moved */
	public const MOVE = 5;
	/** A node (or a subtree of nodes) was inserted */
	public const INSERT = 6;
}
