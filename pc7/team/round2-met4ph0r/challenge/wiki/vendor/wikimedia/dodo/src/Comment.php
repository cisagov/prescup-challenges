<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\WhatWG;

/**
 * Comment node
 */
class Comment extends CharacterData implements \Wikimedia\IDLeDOM\Comment {
	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Comment;

	/**
	 * Create a new Comment node.
	 * @param Document $nodeDocument
	 * @param string $data
	 */
	public function __construct( Document $nodeDocument, $data ) {
		parent::__construct( $nodeDocument, $data );
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::COMMENT_NODE;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeName(): string {
		return "#comment";
	}

	/** @return Comment */
	protected function _subclassCloneNodeShallow(): Node {
		return new Comment( $this->_nodeDocument, $this->_data );
	}

	/** @inheritDoc */
	protected function _subclassIsEqualNode( Node $node ): bool {
		'@phan-var Comment $node'; /** @var Comment $node */
		return ( $this->_data === $node->_data );
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		$data = $this->getData();
		if ( $options['requireWellFormed'] ?? false ) {
			if (
				!WhatWG::is_valid_xml_chars( $data ) ||
				strpos( $data, '--' ) !== false ||
				substr( $data, -1 ) === '-'
			) {
				throw new BadXMLException();
			}
		}
		$markup[] = '<!--' . $data . '-->';
	}

	/** @inheritDoc */
	public function clone(): Comment {
		/*
		* TODO: Does this override directly?
		* Or should we use _subclass_clone_shallow?
		*/
		return new Comment( $this->_nodeDocument, $this->_data );
	}
}
