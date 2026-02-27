<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Document;
use Wikimedia\Dodo\Element;
use Wikimedia\Dodo\Node;

/**
 * A number of DOM algorithms on non-element types like Document and
 * DocumentFragment are defined to return the same results as if they
 * were called on an Element with the same children as that
 * Document/DocumentFragment.  In the CSS specification this is called
 * a "virtual root".
 *
 * This class allows us to reuse code in the Element class by creating
 * a "fake element" class to serve as this virtual root.  In order to
 * remain live, the constructor takes a callback to generate to
 * children of the virtual root on demand.
 *
 * @see https://drafts.csswg.org/selectors-4/#scoping-root
 */
class FakeElement extends Element {
	/** @var callable():(?Node) */
	private $_getFirstChildFunc;

	/**
	 * @param Document $nodeDocument
	 * @param callable():(?Node) $getFirstChildFunc
	 */
	public function __construct( Document $nodeDocument, callable $getFirstChildFunc ) {
		parent::__construct( $nodeDocument, 'fake', Util::NAMESPACE_HTML, null );
		// XXX: Instead of a callable here, this class could take a ParentNode
		// (or Node) since that's the common interface between Element,
		// Document, and DocumentFragment.  But since we only need the
		// first child in practice, taking a callable here preserves the
		// flexibility of using FakeElement in other cases where a
		// "virtual root" is required.
		$this->_getFirstChildFunc = $getFirstChildFunc;
	}

	// ::getFirstChild() helps implement the various serialization methods

	/** @inheritDoc */
	public function getFirstChild(): ?Node {
		return ( $this->_getFirstChildFunc )();
	}

	// Believe it or not, ::_nextElement() is the only method we need to fake
	// to implement querySelector/querySelectorAll

	/** @inheritDoc */
	public function _nextElement( ?Element $root ): ?Element {
		return $this->getFirstElementChild(); // calls ::getFirstChild()
	}
}
