<?php

// AUTOMATICALLY GENERATED.  DO NOT EDIT.
// Use `composer build` to regenerate.

namespace Wikimedia\IDLeDOM;

/**
 * NodeFilter
 *
 * @see https://dom.spec.whatwg.org/#callbackdef-nodefilter
 *
 * @phan-forbid-undeclared-magic-properties
 */
interface NodeFilter {
	/** @var int */
	public const FILTER_ACCEPT = 1;

	/** @var int */
	public const FILTER_REJECT = 2;

	/** @var int */
	public const FILTER_SKIP = 3;

	/** @var int */
	public const SHOW_ALL = 0xFFFFFFFF;

	/** @var int */
	public const SHOW_ELEMENT = 0x1;

	/** @var int */
	public const SHOW_ATTRIBUTE = 0x2;

	/** @var int */
	public const SHOW_TEXT = 0x4;

	/** @var int */
	public const SHOW_CDATA_SECTION = 0x8;

	/** @var int */
	public const SHOW_ENTITY_REFERENCE = 0x10;

	/** @var int */
	public const SHOW_ENTITY = 0x20;

	/** @var int */
	public const SHOW_PROCESSING_INSTRUCTION = 0x40;

	/** @var int */
	public const SHOW_COMMENT = 0x80;

	/** @var int */
	public const SHOW_DOCUMENT = 0x100;

	/** @var int */
	public const SHOW_DOCUMENT_TYPE = 0x200;

	/** @var int */
	public const SHOW_DOCUMENT_FRAGMENT = 0x400;

	/** @var int */
	public const SHOW_NOTATION = 0x800;

	/**
	 * @param Node $node
	 * @return int
	 */
	public function acceptNode( /* Node */ $node ): int;

}
