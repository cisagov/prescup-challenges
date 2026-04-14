<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLOptionElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLOptionElement {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLOptionElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLOptionElement;

}
