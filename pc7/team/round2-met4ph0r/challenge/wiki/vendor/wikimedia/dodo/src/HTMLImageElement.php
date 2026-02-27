<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLImageElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLImageElement {
	use ReferrerPolicy;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLImageElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLImageElement;

	/** @inheritDoc */
	public function getWidth(): int {
		return (int)$this->getAttribute( 'width' );
	}

	/** @inheritDoc */
	public function getHeight(): int {
		return (int)$this->getAttribute( 'height' );
	}

	/** @inheritDoc */
	public function getNaturalWidth(): int {
		// "image is not available"
		return 0;
	}

	/** @inheritDoc */
	public function getNaturalHeight(): int {
		// "image is not available"
		return 0;
	}

	/** @inheritDoc */
	public function setWidth( int $w ): void {
		$this->setAttribute( 'width',
			(string)$w );
	}

	/** @inheritDoc */
	public function setHeight( int $h ): void {
		$this->setAttribute( 'height',
			(string)$h );
	}
}
