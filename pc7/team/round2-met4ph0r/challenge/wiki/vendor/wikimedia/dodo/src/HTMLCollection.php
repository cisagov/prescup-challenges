<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

class HTMLCollection implements \Wikimedia\IDLeDOM\HTMLCollection {

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLCollection;

	/** Create a new empty HTMLCollection */
	public function __construct() {
	}

	/** @inheritDoc */
	public function getLength(): int {
		return 0;
	}

	/** @inheritDoc */
	public function item( int $n ): ?Element {
		return null;
	}

	/** @inheritDoc */
	public function namedItem( string $name ): ?Element {
		return null;
	}
}
