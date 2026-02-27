<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\WhatWG;
use Wikimedia\IDLeDOM\Node as INode;

/**
 * XMLSerializer
 * @see https://w3c.github.io/DOM-Parsing/#the-xmlserializer-interface
 * @phan-forbid-undeclared-magic-properties
 */
class XMLSerializer implements \Wikimedia\IDLeDOM\XMLSerializer {

	/**
	 * Constructs a new XMLSerializer object.
	 */
	public function __construct() {
		/* nothing to do */
	}

	/**
	 * Serializes `root` into a string using an XML serialization.  Throws
	 * a `TypeError` exception if `root` is not a `Node` or an `Attr` object.
	 * @param INode $root
	 * @return string
	 */
	public function serializeToString( $root ): string {
		'@phan-var Node $root';
		$result = [];
		WhatWG::xmlSerialize( $root, [ 'requireWellFormed' => false ], $result );
		return implode( '', $result );
	}
}
