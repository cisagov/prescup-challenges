<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\WhatWG;

/**
 * DocumentType
 */
class DocumentType extends Leaf implements \Wikimedia\IDLeDOM\DocumentType {
	// DOM mixins
	use ChildNode;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\DocumentType;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\DocumentType;

	/**
	 * HACK! For compatibilty with W3C test suite, which assumes that an
	 * access to 'attributes' will return null.
	 * @param string $name
	 * @return mixed
	 */
	protected function _getMissingProp( string $name ) {
		if ( $name === 'attributes' ) {
			return null;
		}
		return parent::_getMissingProp( $name );
	}

	/**
	 * @var string
	 */
	private $_name;
	/**
	 * @var string
	 */
	private $_publicId;
	/**
	 * @var string
	 */
	private $_systemId;

	/**
	 * @param Document $nodeDocument
	 * @param string $name
	 * @param string $publicId
	 * @param string $systemId
	 */
	public function __construct( Document $nodeDocument, string $name, string $publicId = '', string $systemId = '' ) {
		parent::__construct( $nodeDocument );

		$this->_name = $name;
		$this->_publicId = $publicId;
		$this->_systemId = $systemId;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::DOCUMENT_TYPE_NODE;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeName(): string {
		return $this->_name;
	}

	/**
	 * @inheritDoc
	 */
	public function getName(): string {
		return $this->_name;
	}

	/**
	 * @inheritDoc
	 */
	public function getPublicId(): string {
		return $this->_publicId;
	}

	/**
	 * @inheritDoc
	 */
	public function getSystemId(): string {
		return $this->_systemId;
	}

	/* Methods delegated in Node */

	/** @inheritDoc */
	public function _length(): int {
		return 0;
	}

	/** @inheritDoc */
	public function _empty(): bool {
		return true;
	}

	/** @return DocumentType */
	protected function _subclassCloneNodeShallow(): Node {
		return new DocumentType( $this->_nodeDocument, $this->_name, $this->_publicId, $this->_systemId );
	}

	/** @inheritDoc */
	protected function _subclassIsEqualNode( Node $node ): bool {
		'@phan-var DocumentType $node'; /** @var DocumentType $node */
		return (
			$this->_name === $node->_name &&
			$this->_publicId === $node->_publicId &&
			$this->_systemId === $node->_systemId
		);
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		if ( $options['requireWellFormed'] ?? false ) {
			if (
				preg_match(
					// XML PubidChar production
					'|^[\x{0020}\x{000A}\x{000D}a-zA-Z0-9\-\'()+,./:=?;!*#@$_%]*$|Du',
					$this->_publicId
				) !== 1 ||
				!WhatWG::is_valid_xml_chars( $this->_systemId ) ||
				(
					strpos( $this->_systemId, '"' ) !== false &&
					strpos( $this->_systemId, "'" ) !== false
				)
			) {
				throw new \Exception( "Invalid XML characters" );
			}
		}
		$markup[] = '<!DOCTYPE ';
		$markup[] = $this->getName();
		if ( $this->_publicId !== '' ) {
			$markup[] = ' PUBLIC "' . $this->_publicId . '"';
		}
		if ( $this->_systemId !== '' ) {
			if ( $this->_publicId === '' ) {
				$markup[] = " SYSTEM";
			}
			// https://github.com/w3c/DOM-Parsing/issues/71
			$quote = strpos( $this->_systemId, '"' ) === false ? '"' : "'";
			$markup[] = ' ' . $quote . $this->_systemId . $quote;
		}
		$markup[] = '>';
		if ( $options['phpCompat'] ?? false ) {
			$markup[] = "\n";
		}
	}

}
