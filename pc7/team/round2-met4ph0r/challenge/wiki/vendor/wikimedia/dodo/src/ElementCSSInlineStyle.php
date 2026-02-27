<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

trait ElementCSSInlineStyle /* implements \Wikimedia\IDLeDOM\ElementCSSInlineStyle */ {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\ElementCSSInlineStyle;

	/**
	 * @return CSSStyleDeclaration
	 */
	public function getStyle() {
		// XXX: This is just a stub that will allow (and discard) writes
		// to the style property.
		return new CSSStyleDeclaration();
	}

}
