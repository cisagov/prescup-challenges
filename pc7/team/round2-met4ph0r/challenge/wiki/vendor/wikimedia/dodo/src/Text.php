<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;
use Wikimedia\Dodo\Internal\WhatWG;

/**
 * Text node
 */
class Text extends CharacterData implements \Wikimedia\IDLeDOM\Text {
	// DOM mixins
	use Slottable;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\Text;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Text;

	/**
	 * @param Document $nodeDocument
	 * @param string $data
	 */
	public function __construct( Document $nodeDocument, string $data ) {
		parent::__construct( $nodeDocument, $data );
	}

	/**
	 * @inheritDoc
	 */
	public function getNodeType(): int {
		return Node::TEXT_NODE;
	}

	/**
	 * @inheritDoc
	 */
	public function getNodeName(): string {
		return "#text";
	}

	/**
	 * @param Node $node
	 * @return bool
	 */
	protected function _subclassIsEqualNode( Node $node ): bool {
		'@phan-var Text $node'; /** @var Text $node */
		return ( $this->_data === $node->_data );
	}

	/**
	 * @return Text
	 */
	protected function _subclassCloneNodeShallow(): Node {
		return new Text( $this->_nodeDocument, $this->_data );
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		$data = $this->getData();
		if ( $options['requireWellFormed'] ?? false ) {
			if ( !WhatWG::is_valid_xml_chars( $data ) ) {
				throw new BadXMLException();
			}
		}
		$markup[] = strtr(
			$data,
			[
				'&' => '&amp;',
				'<' => '&lt;',
				'>' => '&gt;',
			]
		);
	}

	/**
	 * NOTE: see discussion of UTF-16 code units -vs- unicode code
	 * points in CharacterData::substringData(). Be careful!
	 *
	 * @param int $offset Offset *in unicode code points*
	 * @return Text
	 */
	public function splitText( $offset ) {
		$len = $this->getLength();

		if ( $offset > $len || $offset < 0 ) {
			Util::error( "IndexSizeError" );
		}

		$data = $this->getData();
		$newdata = mb_substr( $data, $offset, null, "utf8" );

		$newnode = new Text( $this->_nodeDocument, $newdata );
		$newnode->_charLength = $len - $offset;

		$this->_data = mb_substr( $data, 0, $offset, "utf8" );
		$this->_charLength = $offset;

		$parent = $this->getParentNode();

		if ( $parent !== null ) {
			$parent->insertBefore( $newnode, $this->getNextSibling() );
		}
		return $newnode;
	}

	/**
	 * @return string
	 */
	public function wholeText() {
		$result = [ $this->getTextContent() ?? '' ];

		for ( $n = $this->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
			if ( $n->getNodeType() !== Node::TEXT_NODE ) {
				break;
			}
			$result[] = $n->getTextContent() ?? '';
		}
		return implode( '', $result );
	}
}
