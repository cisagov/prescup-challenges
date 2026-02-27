<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\Util;

trait ElementContentEditable /* implements \Wikimedia\IDLeDOM\ElementContentEditable */ {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\ElementContentEditable;

	/** @inheritDoc */
	public function getContentEditable(): string {
		'@phan-var Element $this'; /** @var Element $this */
		$val = $this->getAttribute( 'contenteditable' );
		$state = 'inherit';
		if ( $val !== null ) {
			$val = strtr( $val, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
			if ( $val === '' || $val === 'true' ) {
				$state = 'true';
			} elseif ( $val === 'false' ) {
				$state = 'false';
			}
		}
		return $state;
	}

	/** @inheritDoc */
	public function setContentEditable( string $val ): void {
		'@phan-var Element $this'; /** @var Element $this */
		$val = strtr( $val, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz' );
		switch ( $val ) {
			case 'inherit':
				$this->removeAttribute( 'contenteditable' );
				break;
			case 'true':
			case 'false':
				$this->setAttribute( 'contenteditable', $val );
				break;
			default:
				Util::error( 'SyntaxError', 'bad contenteditable value' );
		}
	}
}
