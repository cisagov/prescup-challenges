<?php

namespace MediaWiki\Skins\Vector;

/**
 * @ingroup Skins
 * @package Vector
 * @internal
 */
class SkinVectorLegacy extends SkinVector {
	/**
	 * Whether or not the legacy version of the skin is being used.
	 *
	 * @return bool
	 */
	protected function isLegacy(): bool {
		return true;
	}

	/**
	 * @inheritDoc
	 */
	protected function isLanguagesInContentAt( $location ) {
		return false;
	}
}
