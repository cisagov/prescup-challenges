<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\Util;

/**
 * Returns a new range object that does not update when the node tree mutates.
 *
 * @see https://dom.spec.whatwg.org/#staticrange
 */
class StaticRange extends AbstractRange {

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\StaticRange;

	/**
	 * The new StaticRange(init) constructor steps are:
	 * If init["startContainer"] or init["endContainer"] is a DocumentType or Attr node, then throw an
	 * "InvalidNodeTypeError" DOMException.
	 * Set this’s start to (init["startContainer"], init["startOffset"]) and end to (init["endContainer"],
	 * init["endOffset"]).
	 *
	 * @param \Wikimedia\IDLeDOM\StaticRangeInit|array $init
	 */
	public function __construct( $init ) {
		$init = \Wikimedia\IDLeDOM\StaticRangeInit::cast( $init );
		if (
			$init->getStartContainer() instanceof \Wikimedia\IDLeDOM\DocumentType ||
			$init->getStartContainer() instanceof \Wikimedia\IDLeDOM\Attr ||
			$init->getEndContainer() instanceof \Wikimedia\IDLeDOM\DocumentType ||
			$init->getEndContainer() instanceof \Wikimedia\IDLeDOM\Attr
		) {
			Util::error( 'InvalidNodeTypeError' );
		}
		$startNode = $init->getStartContainer();
		$endNode = $init->getEndContainer();
		'@phan-var Node $startNode'; // @var Node $startNode
		'@phan-var Node $endNode'; // @var Node $endNode
		parent::__construct(
			$startNode, $init->getStartOffset(),
			$endNode, $init->getEndOffset()
		);
	}
}
