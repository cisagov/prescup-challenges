<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLFrameSetElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLFrameSetElement {
	// DOM mixins
	use WindowEventHandlers;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLFrameSetElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLFrameSetElement;
}
