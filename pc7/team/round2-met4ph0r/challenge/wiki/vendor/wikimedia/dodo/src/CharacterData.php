<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\Util;

/**
 * CharacterData.php
 *
 * This uses <u>unicode code points</u> to measure offsets and lengths,
 * not <u>UTF-16 code units</u> (used by the DOM spec and PHP prior to PHP5).
 */
abstract class CharacterData extends Leaf implements \Wikimedia\IDLeDOM\CharacterData, \Countable {
	// DOM mixins
	use ChildNode;
	use NonDocumentTypeChildNode;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\CharacterData;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\CharacterData;

	/** @var string */
	protected $_data;

	/**
	 * Cache the length in *codepoints*.
	 * (See discussion at ::substringData about units here.)
	 * @var ?int
	 */
	protected $_charLength;

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
	 * Create a CharacterData with data (in UTF-8 encoding).
	 * @param Document $nodeDocument the owner document
	 * @param string $data contents, in UTF-8 encoding
	 */
	protected function __construct( Document $nodeDocument, string $data ) {
		parent::__construct( $nodeDocument );
		$this->_data = $data;
		$this->_charLength = null;
	}

	/**
	 * @inheritDoc
	 */
	final public function getNodeValue(): ?string {
		return $this->getData();
	}

	/**
	 * @inheritDoc
	 */
	final public function setNodeValue( ?string $value ): void {
		$this->setData( $value ?? '' );
	}

	/**
	 * @inheritDoc
	 */
	final public function getTextContent(): ?string {
		return $this->getData();
	}

	/**
	 * @inheritDoc
	 */
	final public function setTextContent( ?string $value ): void {
		$this->setData( $value ?? '' );
	}

	/**
	 * DOMString substringData(unsigned long offset, unsigned long count);
	 *
	 * The substringData(offset, count) method must run these steps:
	 *
	 *     If offset is greater than the context object's
	 *     length, throw an INDEX_SIZE_ERR exception and
	 *     terminate these steps.
	 *
	 *     If offset+count is greater than the context
	 *     object's length, return a DOMString whose value is
	 *     the <s>UTF-16 code units</s> <u>code points</u> from the
	 *     offset-th <s>UTF-16 code unit</s> <u>code point</u>
	 *     to the end of data.
	 *
	 *     Return a DOMString whose value is the <s>UTF-16 code
	 *     units</s> <u>code points</u> from the offset-th
	 *     <s>UTF-16 code unit</s> <u>code point</u> to the
	 *     (offset+count)-th <s>UTF-16 code unit</s> <u>code point</u>
	 *     in data.
	 *
	 * PORT NOTES:
	 * In Domino.js, checking was done to ensure $offset and $count
	 * were integers and not-undefined. Here we just use type hints.
	 *
	 * The DOM spec requires that the offset and count be in *UTF-16 units*
	 * and the PHP \DOMText etc classes originally did this (and the PHP
	 * docs still say that's how things should work).  In PHP 5 the
	 * implementation was changed to measure things in *codepoints*,
	 * so that surrogates are no longer counted. This is very sensible,
	 * so we've chosen to be compatible w/ current PHP behavior, and
	 * this *incompatible* with DOM spec and with PHP documentation
	 * (which doesn't match the current PHP implementation).
	 * Be careful!
	 *
	 * @param int $offset
	 * @param int $count
	 * @return string
	 */
	public function substringData( int $offset, int $count ): string {
		// Silly conversion to an int32 to make our test suites happy
		$offset &= 0xFFFFFFFF;
		$count &= 0xFFFFFFFF;

		$len = $this->getLength();
		if ( $offset > $len || $offset < 0 || $count < 0 ) {
			Util::error( "IndexSizeError" );
		}

		return mb_substr( $this->_data, $offset, $count, "utf8" );
	}

	/**
	 * void appendData(DOMString data);
	 *
	 * The appendData(data) method must append data to the context
	 * object's data.
	 *
	 * PORT NOTES: Again, for the number of arguments, we can just
	 * use the function prototype to check.
	 *
	 * @param string $data
	 */
	public function appendData( string $data ): void {
		$this->_data .= $data;
		$this->_charLength = null;
		if ( $this->getIsConnected() ) {
			$this->_nodeDocument->_mutateValue( $this );
		}
	}

	/**
	 * void insertData(unsigned long offset, DOMString data);
	 *
	 * The insertData(offset, data) method must run these steps:
	 *
	 *     If offset is greater than the context object's
	 *     length <u>in code points</u>, throw an INDEX_SIZE_ERR
	 *     exception and terminate these steps.
	 *
	 *     Insert data into the context object's data after
	 *     offset <s>UTF-16 code units</s> <u>code points</u>.
	 *
	 * NOTE: see discussion of UTF-16 code units -vs- unicode code
	 * points in ::substringData() above. Be careful!
	 *
	 * @param int $offset
	 * @param string $data
	 */
	public function insertData( int $offset, string $data ): void {
		$this->replaceData( $offset, 0, $data );
	}

	/**
	 * void deleteData(unsigned long offset, unsigned long count);
	 *
	 * The deleteData(offset, count) method must run these steps:
	 *
	 *     If offset is greater than the context object's
	 *     length <u>in code points</u>, throw an INDEX_SIZE_ERR
	 *     exception and terminate these steps.
	 *
	 *     If offset+count is greater than the context
	 *     object's length <u>in code points</u> let count be
	 *     length-offset.
	 *
	 *     Starting from offset <s>UTF-16 code units</s> <u>code points</u>
	 *     remove count <s>UTF-16 code units</s> <u>code points</u> from
	 *     the context object's data.
	 *
	 * NOTE: see discussion of UTF-16 code units -vs- unicode code
	 * points in ::substringData() above. Be careful!
	 *
	 * @param int $offset
	 * @param int $count
	 */
	public function deleteData( int $offset, int $count ): void {
		$this->replaceData( $offset, $count, '' );
	}

	/**
	 * void replaceData(unsigned long offset, unsigned long count,
	 *          DOMString data);
	 *
	 * The replaceData(offset, count, data) method must act as
	 * if the deleteData() method is invoked with offset and
	 * count as arguments followed by the insertData() method
	 * with offset and data as arguments and re-throw any
	 * exceptions these methods might have thrown.
	 *
	 * NOTE: see discussion of UTF-16 code units -vs- unicode code
	 * points in ::substringData() above.
	 *
	 * @param int $offset
	 * @param int $count
	 * @param string $data
	 */
	public function replaceData( int $offset, int $count, string $data ): void {
		$len = $this->getLength();

		// Silly conversion to an int32 to make our test suites happy
		$offset &= 0xFFFFFFFF;
		$count &= 0xFFFFFFFF;

		if ( $offset > $len || $offset < 0 ) {
			Util::error( "IndexSizeError" );
		}

		if ( $offset + $count > $len ) {
			$count = $len - $offset;
		}

		// Fast path
		if ( $offset === 0 && $count === $len ) {
			$this->_data = $data;
		} else {
			$curtext = $this->_data;
			$prefix = mb_substr( $curtext, 0, $offset, "utf8" );
			$suffix = mb_substr( $curtext, ( $offset + $count ), null, "utf8" );

			$this->_data = $prefix . $data . $suffix;
		}
		$this->_charLength = null;
		if ( $this->getIsConnected() ) {
			$this->_nodeDocument->_mutateValue( $this );
		}
	}

	/**
	 * NOTE: see discussion of UTF-16 code units -vs- unicode code
	 * points in ::substringData() above. Be careful!
	 * @inheritDoc
	 */
	public function getLength(): int {
		if ( $this->_charLength === null ) {
			$this->_charLength = mb_strlen( $this->_data, "utf8" );
		}
		return $this->_charLength;
	}

	/** @inheritDoc */
	public function getData(): string {
		return $this->_data;
	}

	/** @inheritDoc */
	public function setData( ?string $value ): void {
		$this->_data = $value ?? '';
		$this->_charLength = null;
		if ( $this->getIsConnected() ) {
			$this->_nodeDocument->_mutateValue( $this );
		}
	}

	/** @inheritDoc */
	public function _length(): int {
		return $this->getLength();
	}

	/** @inheritDoc */
	public function _empty(): bool {
		 // utf8 code units or unicode code points, doesn't matter:
		return strlen( $this->_data ) === 0;
	}

	/**
	 * This is a non-standard extension, but it allows count() to be used
	 * on CharacterData nodes in the same way that .length is used on them
	 * in JavaScript -- and makes some of our WPT test cases pass.
	 * @return int
	 */
	public function count(): int {
		return $this->_length();
	}
}
