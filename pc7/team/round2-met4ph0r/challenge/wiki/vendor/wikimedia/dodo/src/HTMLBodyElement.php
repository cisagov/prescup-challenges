<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLBodyElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLBodyElement {
	// DOM mixins
	use WindowEventHandlers;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLBodyElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLBodyElement;
}
