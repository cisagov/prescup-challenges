<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLStyleElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLStyleElement {
	// DOM mixins
	use LinkStyle;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLStyleElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLStyleElement;

}
