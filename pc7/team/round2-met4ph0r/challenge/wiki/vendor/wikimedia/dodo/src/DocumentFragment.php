<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\Dodo\Internal\FakeElement;
use Wikimedia\Dodo\Internal\FilteredElementList;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;

/**
 * DocumentFragment
 */
class DocumentFragment extends ContainerNode implements \Wikimedia\IDLeDOM\DocumentFragment {
	// DOM mixins
	use NonElementParentNode;
	use ParentNode;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\DocumentFragment;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\DocumentFragment;

	/**
	 * @param string $name
	 * @return mixed
	 */
	protected function _getMissingProp( string $name ) {
		switch ( $name ) {
			case 'attributes':
				// HACK! For compatibilty with W3C test suite, which
				// assumes that an access to 'attributes' will return
				// null.
				return null;
			case 'innerHTML':
				return $this->getInnerHTML(); // nonstandard but handy
			case 'outerHTML':
				return $this->getOuterHTML();  // nonstandard but handy
			default:
				return parent::_getMissingProp( $name );
		}
	}

	/** @inheritDoc */
	public function __construct( Document $nodeDocument ) {
		parent::__construct( $nodeDocument );
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::DOCUMENT_FRAGMENT_NODE;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeName(): string {
		return "#document-fragment";
	}

	/** @return DocumentFragment */
	protected function _subclassCloneNodeShallow(): Node {
		return new DocumentFragment( $this->_nodeDocument );
	}

	/** @inheritDoc */
	protected function _subclassIsEqualNode( Node $node ): bool {
		// Any two document fragments are shallowly equal.
		// Node.isEqualNode() will test their children for equality
		return true;
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		for ( $child = $this->getFirstChild(); $child !== null; $child = $child->getNextSibling() ) {
			$child->_xmlSerialize(
				$namespace, $prefixMap, $prefixIndex, $options,
				$markup
			);
		}
	}

	/** @inheritDoc */
	public function querySelectorAll( string $selectors ) {
		return $this->_fakeElement()->querySelectorAll( $selectors );
	}

	/** @inheritDoc */
	public function querySelector( string $selectors ) {
		return $this->_fakeElement()->querySelector( $selectors );
	}

	/** @inheritDoc */
	public function getElementById( string $id ) {
		$nl = new FilteredElementList( $this->_fakeElement(), static function ( $el ) use ( $id ) {
			return $el->getAttribute( 'id' ) === $id;
		} );
		return $nl->getLength() > 0 ? $nl->item( 0 ) : null;
	}

	/** @inheritDoc */
	public function _getElementsById( string $id ): array {
		return $this->_fakeElement()->_getElementsById( $id );
	}

	/**
	 * Create a FakeElement so that we can invoke methods of Element on
	 * DocumentFragment "as if it were an element".
	 * @return FakeElement
	 */
	private function _fakeElement(): FakeElement {
		return new FakeElement( $this->_nodeDocument, function () {
			return $this->getFirstChild();
		} );
	}

	// Non-standard methods for PHP compatibility

	/**
	 * Appends raw XML data to a DOMDocumentFragment.
	 *
	 * This method is not part of the DOM standard.
	 * @see https://www.php.net/manual/en/domdocumentfragment.appendxml.php
	 *
	 * @param string $data XML to append.
	 * @return bool `true` on success or `false` on failure.
	 */
	public function appendXML( string $data ): bool {
		try {
			// the ::appendXML method allow multiple elements, whereas
			// ::_parseXml notionally only allows a single element.
			// So we need to wrap the data as a single element, then
			// unwrap it. (Ugh)
			$uniqueName = "DodoUniqueRootName";
			for ( $i = 0; ; $i++ ) {
				if ( strpos( $data, "$uniqueName$i" ) === false ) {
					break;
				}
			}
			$data = "<$uniqueName$i>$data</$uniqueName$i>";
			DOMParser::_parseXml( $this, $data, [ 'skipRoot' => true ] );
			return true;
		} catch ( BadXMLException $e ) {
			return false;
		}
	}

	// Non-standard, but useful (github issue #73)

	/** @return string the inner HTML of this DocumentFragment */
	public function getInnerHTML(): string {
		return $this->_fakeElement()->getInnerHTML();
	}

	/** @return string the outer HTML of this DocumentFragment */
	public function getOuterHTML(): string {
		return $this->getInnerHTML();
	}
}
