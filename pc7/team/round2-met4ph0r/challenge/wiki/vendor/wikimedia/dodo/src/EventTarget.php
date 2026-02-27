<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

/**
 * @phan-forbid-undeclared-magic-properties
 */
class EventTarget implements \Wikimedia\IDLeDOM\EventTarget {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\EventTarget;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\EventTarget;
}
