<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\Zest;

trait ParentNode /* implements \Wikimedia\IDLeDOM\ParentNode */ {
	use \Wikimedia\IDLeDOM\Stub\ParentNode;

	/**
	 * @return ?Element
	 */
	public function getFirstElementChild(): ?Element {
		'@phan-var Node $this'; // @var Node $this
		for ( $kid = $this->getFirstChild();  $kid !== null;  $kid = $kid->getNextSibling() ) {
			if ( $kid->getNodeType() === Node::ELEMENT_NODE ) {
				'@phan-var Element $kid'; // @var Element $kid
				return $kid;
			}
		}
		return null;
	}

	/**
	 * @return ?Element
	 */
	public function getLastElementChild(): ?Element {
		'@phan-var Node $this'; // @var Node $this
		for ( $kid = $this->getLastChild();  $kid !== null;  $kid = $kid->getPreviousSibling() ) {
			if ( $kid->getNodeType() === Node::ELEMENT_NODE ) {
				'@phan-var Element $kid'; // @var Element $kid
				return $kid;
			}
		}
		return null;
	}

	/**
	 * @param string $selectors
	 * @return ?Element
	 */
	public function querySelector( string $selectors ) {
		'@phan-var \Wikimedia\IDLeDOM\ParentNode $this'; // @var \Wikimedia\IDLeDOM\ParentNode $this
		$nodes = Zest::find( $selectors, $this );
		return $nodes[0] ?? null;
	}

	/**
	 * @param string $selectors
	 * @return NodeList
	 */
	public function querySelectorAll( string $selectors ) {
		'@phan-var \Wikimedia\IDLeDOM\ParentNode $this'; // @var \Wikimedia\IDLeDOM\ParentNode $this
		$nl = new NodeList();
		$nl->_splice( 0, 0, Zest::find( $selectors, $this ) );
		return $nl;
	}

	/**
	 * This is a non-standard Dodo extension that interfaces with the Zest
	 * CSS selector library to allow quick lookup by ID *even if there are
	 * multiple nodes in the document with the same ID*.
	 * @param string $id
	 * @return array<Element>
	 */
	abstract public function _getElementsById( string $id ): array;
}
