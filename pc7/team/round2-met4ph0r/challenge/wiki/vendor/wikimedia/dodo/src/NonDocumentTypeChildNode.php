<?php

declare( strict_types = 1 );
// phpcs doesn't like @copyDoc, apparently:
// phpcs:disable MediaWiki.Commenting.FunctionAnnotations.UnrecognizedAnnotation
// phpcs:disable MediaWiki.Commenting.FunctionComment.MissingParamTag
// phpcs:disable MediaWiki.Commenting.FunctionComment.MissingReturn

namespace Wikimedia\Dodo;

/**
 * NonDocumentTypeChildNode
 *
 * This is a mixin used by Element and CharacterData.
 */
trait NonDocumentTypeChildNode /* implements \Wikimedia\IDLeDOM\NonDocumentTypeChildNode */ {
	use \Wikimedia\IDLeDOM\Stub\NonDocumentTypeChildNode;

	/**
	 * @copyDoc \Wikimedia\IDLeDOM\NonDocumentTypeChildNode::getNextElementSibling()
	 */
	public function getNextElementSibling() {
		'@phan-var Node $this'; // @var Node $this
		if ( $this->_parentNode === null ) {
			return null;
		}

		for ( $n = $this->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
			if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
				return $n;
			}
		}
		return null;
	}

	/**
	 * @copyDoc \Wikimedia\IDLeDOM\NonDocumentTypeChildNode::getPreviousElementSibling()
	 */
	public function getPreviousElementSibling() {
		'@phan-var Node $this'; // @var Node $this
		if ( $this->_parentNode === null ) {
			return null;
		}
		for ( $n = $this->getPreviousSibling(); $n !== null; $n = $n->getPreviousSibling() ) {
			if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
				return $n;
			}
		}
		return null;
	}
}
