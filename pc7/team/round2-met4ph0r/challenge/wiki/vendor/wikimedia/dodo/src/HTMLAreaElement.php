<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLAreaElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLAreaElement {
	use HTMLHyperlinkElementUtils;
	use ReferrerPolicy;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLAreaElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLAreaElement;
}
