<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;
use Wikimedia\Dodo\Internal\WhatWG;

/**
 * ProcessingInstruction node
 */
class ProcessingInstruction extends CharacterData implements \Wikimedia\IDLeDOM\ProcessingInstruction {
	// DOM mixins
	use LinkStyle;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\ProcessingInstruction;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\ProcessingInstruction;

	/**
	 * @var string
	 */
	private $_target;

	/**
	 * @param Document $nodeDocument
	 * @param string $target
	 * @param string $data
	 */
	public function __construct( Document $nodeDocument, string $target, string $data ) {
		parent::__construct( $nodeDocument, $data );
		$this->_target = $target;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::PROCESSING_INSTRUCTION_NODE;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeName(): string {
		return $this->_target;
	}

	/**
	 * Delegated methods from Node
	 *
	 * @return ProcessingInstruction
	 */
	protected function _subclassCloneNodeShallow(): Node {
		return new ProcessingInstruction( $this->_nodeDocument, $this->_target, $this->_data );
	}

	/**
	 * @param Node $node
	 * @return bool
	 */
	protected function _subclassIsEqualNode( Node $node ): bool {
		'@phan-var ProcessingInstruction $node'; /** @var ProcessingInstruction $node */
		return ( $this->_target === $node->_target && $this->_data === $node->_data );
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		$data = $this->getData();
		if ( $options['requireWellFormed'] ?? false ) {
			if (
				strpos( $this->_target, ':' ) !== false ||
				Util::toAsciiLowercase( $this->_target ) === 'xml' ||
				!WhatWG::is_valid_xml_chars( $data ) ||
				strpos( $data, '?>' ) !== false
			) {
				throw new BadXMLException();
			}
		}
		$markup[] = '<?' . $this->_target . ' ' . $data . '?>';
	}
}
