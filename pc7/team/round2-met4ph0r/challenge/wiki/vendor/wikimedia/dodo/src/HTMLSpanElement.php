<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLSpanElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLSpanElement {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLSpanElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLSpanElement;

}
