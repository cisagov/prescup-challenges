<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLFieldSetElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLFieldSetElement {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLFieldSetElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLFieldSetElement;
}
