<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLLegendElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLLegendElement {
	use ReferrerPolicy;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLLegendElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLLegendElement;
}
