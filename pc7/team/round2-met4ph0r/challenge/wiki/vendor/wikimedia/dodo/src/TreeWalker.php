<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

/**
 * @phan-forbid-undeclared-magic-properties
 */
abstract class TreeWalker implements \Wikimedia\IDLeDOM\TreeWalker {
	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\TreeWalker;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\TreeWalker;
	use UnimplementedTrait;
}
