<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLIFrameElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLIFrameElement {
	use ReferrerPolicy;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLIFrameElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLIFrameElement;
}
