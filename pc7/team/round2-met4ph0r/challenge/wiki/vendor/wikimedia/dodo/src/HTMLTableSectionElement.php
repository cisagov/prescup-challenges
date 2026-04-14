<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLTableSectionElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLTableSectionElement {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLTableSectionElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLTableSectionElement;

}
