<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\FakeElement;

trait NonElementParentNode /* implements \Wikimedia\IDLeDOM\NonElementParentNode */ {
	use \Wikimedia\IDLeDOM\Stub\NonElementParentNode;

	// We could move getElementById() definition here, but it is different
	// for Document and DocumentFragment

	// We could move querySelector()/querySelectorAll() definitions here,
	// but both Document and Element call Zest directly, only DocumentFragment
	// needs to use a FakeElement

	/**
	 * Create a FakeElement so that we can invoke methods of Element on
	 * Document or DocumentFragment "as if it were an element".
	 * @return FakeElement
	 */
	abstract public function _fakeElement(): FakeElement;
}
