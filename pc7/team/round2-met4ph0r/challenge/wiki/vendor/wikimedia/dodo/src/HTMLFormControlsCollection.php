<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLFormControlsCollection extends HTMLCollection implements \Wikimedia\IDLeDOM\HTMLFormControlsCollection {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLFormControlsCollection;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLFormControlsCollection;
}
