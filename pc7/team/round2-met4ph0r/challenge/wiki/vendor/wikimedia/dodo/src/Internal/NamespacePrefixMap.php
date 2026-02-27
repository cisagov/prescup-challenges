<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Wikimedia\IDLeDOM\Element;

/**
 * A namespace prefix map.
 * @see https://w3c.github.io/DOM-Parsing/#dfn-namespace-prefix-map
 */
class NamespacePrefixMap {
	/**
	 * @var array<string,string[]> Map namespaces to a list of prefixes
	 */
	private $map = [];
	/**
	 * @var array<string,string> Maps prefixes to the namespaces they represent.
	 */
	private $reverseMap = [];

	/**
	 * Create a new empty namespace prefix map.
	 */
	public function __construct() {
	}

	/**
	 * Keys can include 'null'; use a prefix to ensure that we can
	 * represent all valid keys as a string.
	 * @param ?string $key Key to a namespace prefix map
	 * @return string Key that can be used for a PHP associative array
	 */
	private static function makeKey( ?string $key ): string {
		return $key === null ? 'null' : "!$key";
	}

	/**
	 * Check if a prefix string is found in a namespace prefix map.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-found
	 * @param ?string $namespace
	 * @param string $prefix
	 * @return bool
	 */
	public function found( ?string $namespace, string $prefix ) {
		$key = self::makeKey( $namespace );
		return ( $this->reverseMap[$prefix] ?? null ) === $key;
	}

	/**
	 * Add a prefix string to the namespace prefix map.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-add
	 * @param ?string $namespace
	 * @param string $prefix
	 */
	public function add( ?string $namespace, string $prefix ) {
		$key = self::makeKey( $namespace );
		// Remove any other mapping for $prefix before adding it to the map
		# https://github.com/w3c/DOM-Parsing/issues/45
		if ( array_key_exists( $prefix, $this->reverseMap ) ) {
			$otherKey = $this->reverseMap[$prefix];
			$idx = array_search( $prefix, $this->map[$otherKey] );
			array_splice( $this->map[$otherKey], $idx, 1 );
			if ( count( $this->map[$otherKey] ) === 0 ) {
				unset( $this->map[$otherKey] );
			}
		}
		if ( !array_key_exists( $key, $this->map ) ) {
			$this->map[$key] = [];
		}
		$this->map[$key][] = $prefix;
		$this->reverseMap[$prefix] = $key;
	}

	/**
	 * Record the namespace information for an element, given this namespace
	 * prefix map and a local prefixes map.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-recording-the-namespace-information
	 * @param Element $element
	 * @param array<string,string> &$localPrefixMap
	 * @return ?string
	 */
	public function recordNamespaceInformation(
		Element $element, array &$localPrefixMap
	): ?string {
		$result = null;

		foreach ( $element->getAttributes() as $attr ) {
			$attrNamespace = $attr->getNamespaceURI();
			$attrPrefix = $attr->getPrefix();
			if ( $attrNamespace === Util::NAMESPACE_XMLNS ) {
				if ( $attrPrefix === null ) {
					// $attr is a default namespace declaration
					$result = $attr->getValue();
					continue;
				}
				// $attr is a namespace prefix definition
				$prefixDefinition = $attr->getLocalName();
				$namespaceDefinition = $attr->getValue();
				if ( $namespaceDefinition === Util::NAMESPACE_XML ) {
					continue;
				} elseif ( $namespaceDefinition === '' ) {
					$namespaceDefinition = null;
				}
				if ( $this->found( $namespaceDefinition, $prefixDefinition ) ) {
					continue;
				}
				$this->add( $namespaceDefinition, $prefixDefinition );
				$localPrefixMap[$prefixDefinition] = $namespaceDefinition ?? '';
			}
		}
		return $result;
	}

	/**
	 * Retrieve a preferred prefix string.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-retrieving-a-preferred-prefix-string
	 * @param ?string $namespace
	 * @param ?string $preferredPrefix
	 * @return ?string
	 */
	public function retrievePreferredPrefix(
		?string $namespace,
		?string $preferredPrefix
	): ?string {
		$key = self::makeKey( $namespace );
		if (
			$preferredPrefix !== null &&
			( $this->reverseMap[$preferredPrefix] ?? null ) === $key
		) {
			return $preferredPrefix;
		}
		if ( array_key_exists( $key, $this->map ) ) {
			// return last prefix in list
			$candidatesList = $this->map[$key];
			return $candidatesList[count( $candidatesList ) - 1];
		} else {
			return null; // not found!
		}
	}

	/**
	 * Copy a namespace prefix map.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-copy-a-namespace-prefix-map
	 * @return NamespacePrefixMap
	 */
	public function clone(): NamespacePrefixMap {
		$c = new NamespacePrefixMap();
		// Let PHP handle the deep array copy for us
		$c->map = $this->map;
		$c->reverseMap = $this->reverseMap;
		return $c;
	}

	/**
	 * Generate a prefix given a map, a string new namespace, and a reference
	 * to a prefix index.
	 * @see https://w3c.github.io/DOM-Parsing/#generating-namespace-prefixes
	 * @param ?string $newNamespace
	 * @param int &$prefixIndex
	 * @return string the generated prefix
	 */
	public function generatePrefix(
		?string $newNamespace, int &$prefixIndex
	) {
		while ( true ) {
			$generatedPrefix = 'ns' . $prefixIndex;
			$prefixIndex += 1;
			if ( array_key_exists( $generatedPrefix, $this->reverseMap ) ) {
				// https://github.com/w3c/DOM-Parsing/issues/44
				continue;
			}
			$this->add( $newNamespace, $generatedPrefix );
			return $generatedPrefix;
		}
	}
}
