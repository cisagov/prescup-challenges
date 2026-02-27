<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

/**
 * NodeFilter
 *
 * Stub for https://dom.spec.whatwg.org/#interface-nodefilter
 * @phan-forbid-undeclared-magic-properties
 */
abstract class NodeFilter implements \Wikimedia\IDLeDOM\NodeFilter {
	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\NodeFilter;

	/**
	 * @inheritDoc
	 */
	abstract public function acceptNode( /* Node */ $node ): int;
}
