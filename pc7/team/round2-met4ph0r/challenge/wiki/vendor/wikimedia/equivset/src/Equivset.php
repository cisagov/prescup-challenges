<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

namespace Wikimedia\Equivset;

use ArrayIterator;
use IteratorAggregate;
use LogicException;
use Wikimedia\Equivset\Exception\EquivsetException;

/**
 * Default Equivset
 */
class Equivset implements EquivsetInterface, IteratorAggregate {

	/**
	 * @var array
	 */
	protected $data;

	/**
	 * @var string
	 */
	protected $serializedPath;

	/**
	 * Equivset
	 *
	 * @param array $data Equivalent Set
	 * @param string $serializedPath Path of the serialized equivset array.
	 */
	public function __construct( array $data = [], $serializedPath = '' ) {
		$this->data = $data;
		$this->serializedPath = $serializedPath ?: __DIR__ . '/../dist/equivset.ser';
	}

	/**
	 * Gets the equivset.
	 *
	 * @return array An associative array of equivalent characters.
	 */
	public function all() {
		if ( !$this->data ) {
			$this->data = $this->load();
		}

		return $this->data;
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $value The string to normalize against the equivset.
	 *
	 * @return string
	 */
	public function normalize( $value ) {
		$data = $this->all();

		return strtr( $value, $data );
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $str1 The first string.
	 * @param string $str2 The second string.
	 *
	 * @return bool
	 */
	public function isEqual( $str1, $str2 ) {
		return $this->normalize( $str1 ) === $this->normalize( $str2 );
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $key The character that was used.
	 *
	 * @return bool If the character has an equivalent.
	 */
	public function has( $key ) {
		$data = $this->all();

		return array_key_exists( $key, $data );
	}

	/**
	 * {@inheritdoc}
	 *
	 * @param string $key The character that was used.
	 *
	 * @return string The equivalent character.
	 *
	 * @throws LogicException If character does not exist.
	 */
	public function get( $key ) {
		$data = $this->all();

		if ( !array_key_exists( $key, $data ) ) {
			throw new LogicException( 'Equivalent Character Not Found' );
		}

		return $data[$key];
	}

	/**
	 * {@inheritdoc}
	 *
	 * @return ArrayIterator The complete Equivset.
	 */
	public function getIterator(): ArrayIterator {
		return new ArrayIterator( $this->all() );
	}

	/**
	 * Gets the equivset.
	 *
	 * @return array An associative array of equivalent characters.
	 *
	 * @throws EquivsetException If the serialized equivset is not loaded.
	 */
	protected function load() {
		if ( !file_exists( $this->serializedPath ) ) {
			throw new EquivsetException( 'Serialized equivset is missing' );
		}

		if ( !is_readable( $this->serializedPath ) ) {
			throw new EquivsetException( 'Serialized equivset is unreadable' );
		}

		// file_get_contents() will not fail at this point since none of the
		// conditions that can cause a failure can happen at this point.
		// @see http://php.net/manual/en/function.file-get-contents.php
		$contents = file_get_contents( $this->serializedPath );

		$data = unserialize( $contents );

		if ( $data === false ) {
			throw new EquivsetException( 'Unserializing serialized equivset failed' );
		}

		return $data;
	}
}
