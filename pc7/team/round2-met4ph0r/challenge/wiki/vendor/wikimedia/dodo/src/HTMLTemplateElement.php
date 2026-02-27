<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

class HTMLTemplateElement extends HTMLElement implements \Wikimedia\IDLeDOM\HTMLTemplateElement {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLTemplateElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLTemplateElement;

	/** @var DocumentFragment */
	private $_contentFragment;

	/**
	 * Create a new HTMLTemplateElement.
	 * @param Document $doc
	 * @param string $lname
	 * @param ?string $prefix
	 */
	public function __construct( Document $doc, string $lname, ?string $prefix = null ) {
		parent::__construct( $doc, $lname, $prefix );
		$this->_contentFragment =
			$doc->_getTemplateDoc()->createDocumentFragment();
	}

	/** @inheritDoc */
	public function getContent(): DocumentFragment {
		return $this->_contentFragment;
	}

	/** @inheritDoc */
	public function _htmlSerialize( array &$result, array $options ): void {
		$this->_contentFragment->_htmlSerialize( $result, $options );
	}
}
