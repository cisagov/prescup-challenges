<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedTrait;

class CDATASection extends Text implements \Wikimedia\IDLeDOM\CDATASection {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\CDATASection;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\CDATASection;

	/**
	 * @inheritDoc
	 */
	final public function getNodeType(): int {
		return Node::CDATA_SECTION_NODE;
	}

	/**
	 * @inheritDoc
	 */
	public function getNodeName(): string {
		return "#cdata-section";
	}

	/** @inheritDoc */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		// See https://github.com/w3c/DOM-Parsing/issues/38
		$data = $this->getData();
		if ( $options['requireWellFormed'] ?? false ) {
			if ( strpos( $data, ']]>' ) !== false ) {
				throw new BadXMLException();
			}
		}
		$markup[] = '<![CDATA[';
		$markup[] = $this->getData();
		$markup[] = ']]>';
	}
}
