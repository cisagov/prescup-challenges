<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\BadXMLException;
use Wikimedia\IDLeDOM\DOMParserSupportedType;
use Wikimedia\RemexHtml\DOM\DOMBuilder;
use Wikimedia\RemexHtml\Tokenizer\NullTokenHandler;
use Wikimedia\RemexHtml\Tokenizer\Tokenizer;
use Wikimedia\RemexHtml\TreeBuilder\Dispatcher;
use Wikimedia\RemexHtml\TreeBuilder\Element as TreeElement;
use Wikimedia\RemexHtml\TreeBuilder\TreeBuilder;
use XMLReader;

/**
 * DOMParser
 * @see https://dom.spec.whatwg.org/#interface-domparser
 * @phan-forbid-undeclared-magic-properties
 */
class DOMParser implements \Wikimedia\IDLeDOM\DOMParser {

	/**
	 * @param string $string
	 * @param string $type
	 * @return Document
	 */
	public function parseFromString( string $string, /* DOMParserSupportedType */ string $type ) {
		$type = DOMParserSupportedType::cast( $type );
		$doc = new Document();
		switch ( $type ) {
		case DOMParserSupportedType::text_html:
			$doc->_setContentType( 'text/html', true );
			self::_parseHtml( $doc, $string, [] );
			return $doc;
		default:
			# According to spec, this is a Document not an XMLDocument
			$doc->_setContentType( $type, false );
			// XXX if we throw an XML well-formedness error here, we're
			/// supposed to make a document describing it, instead of
			// throwing an exception.
			self::_parseXml( $doc, $string, [] );
			return $doc;
		}
	}

	/**
	 * Create an HTML parser, parsing the string as UTF-8.
	 * @param Document $doc
	 * @param string $string
	 * @param array $options
	 * @return Document
	 * @internal
	 */
	public static function _parseHtml( Document $doc, string $string, array $options ) {
		$domBuilder = new class( $doc, $options ) extends DOMBuilder {
				/** @var Document */
				public $doc;
				/** @var array */
				private $options;
				/** @var bool */
				public $sawRealHead = false;
				/** @var bool */
				public $sawRealBody = false;

				/**
				 * Create a new DOMBuilder and store the document and
				 * options array.
				 * @param Document $doc
				 * @param array $options
				 */
				public function __construct( Document $doc, array $options ) {
					parent::__construct( [
						'suppressHtmlNamespace' => false,
						'suppressIdAttribute' => true,
						'domExceptionClass' => DOMException::class,
					] );
					$this->doc = $doc;
					$this->options = $options;
				}

				/** @inheritDoc */
				protected function createDocument(
					string $doctypeName = null,
					string $public = null,
					string $system = null
				) {
					// Force this to be an HTML document (not an XML document)
					$this->doc->_setContentType( 'text/html', true );
					$this->maybeRemoveDoctype();
					if ( $this->options['phpCompat'] ?? false ) {
						$this->setDoctype(
							'html',
							'-//W3C//DTD HTML 4.0 Transitional//EN',
							'http://www.w3.org/TR/REC-html40/loose.dtd'
						);
					}
					return $this->doc;
				}

				/**
				 * Remove a DocumentType from the given document if one
				 * is present.
				 */
				private function maybeRemoveDoctype() {
					$doctype = $this->doc->getDoctype();
					if ( $doctype !== null ) {
						$doctype->remove();
					}
				}

				/**
				 * Replace any existing doctype for this document with
				 * new one.
				 * @param ?string $name
				 * @param ?string $public
				 * @param ?string $system
				 */
				private function setDoctype( $name, $public, $system ): void {
					$this->maybeRemoveDoctype();
					if ( $name !== '' && $name !== null ) {
						$doctype = new DocumentType(
							$this->doc, $name, $public ?? '', $system ?? ''
						);
						$this->doc->appendChild( $doctype );
					}
				}

				/** @inheritDoc */
				public function doctype( $name, $public, $system, $quirks, $sourceStart, $sourceLength ) {
					$this->setDoctype( $name, $public, $system );
					// Set quirks mode on our document.
					switch ( $quirks ) {
					case TreeBuilder::NO_QUIRKS:
						$this->doc->_setQuirksMode( 'no-quirks' );
						break;
					case TreeBuilder::LIMITED_QUIRKS:
						$this->doc->_setQuirksMode( 'limited-quirks' );
						break;
					case TreeBuilder::QUIRKS:
						$this->doc->_setQuirksMode( 'quirks' );
						break;
					}
				}

				/** @inheritDoc */
				public function insertElement(
					$preposition, $refElement,
					TreeElement $element,
					$void, $sourceStart, $sourceLength
				) {
					if ( $element->name === 'head' && $sourceLength > 0 ) {
						$this->sawRealHead = true;
					}
					if ( $element->name === 'body' && $sourceLength > 0 ) {
						$this->sawRealBody = true;
					}
					parent::insertElement(
						$preposition, $refElement, $element, $void,
						$sourceStart, $sourceLength
					);
				}

				/** @inheritDoc */
				protected function createNode( TreeElement $element ) {
					// Simplified version of this method which eliminates
					// the various workarounds necessary when using the
					// PHP dom extension

					// It also deliberately bypasses some character validity
					// checking done in Document::createElementNS(), which
					// is per-spec. (We need to prevent createElementNS from
					// trying to parse `name` as a `qname`.)
					$node = $this->doc->_createElementNS(
							$element->name,
							$element->namespace,
							null /* prefix */
					);
					foreach ( $element->attrs->getObjects() as $attr ) {
						// This also bypasses checks & prefix parsing
						if ( $attr->namespaceURI === null ) {
							$node->_setAttribute(
								$attr->qualifiedName, $attr->value
							);
						} else {
							$node->_setAttributeNS(
								$attr->namespaceURI, $attr->prefix,
								$attr->localName, $attr->value
							);
						}
					}
					$element->userData = $node;
					return $node;
				}

				/**
				 * This is a reimplementation for efficiency only; the
				 * code should be identical to (and kept in sync with)
				 * Remex.  We just use method access instead of getters,
				 * since this is a hot path through the HTML parser.
				 * @inheritDoc
				 */
				public function characters(
					$preposition, $refElement, $text, $start, $length,
					$sourceStart, $sourceLength
				) {
					// Parse $preposition and $refElement as in self::insertNode()
					if ( $preposition === TreeBuilder::ROOT ) {
						$parent = $this->doc;
						$refNode = null;
					} elseif ( $preposition === TreeBuilder::BEFORE ) {
						$parent = $refElement->userData->parentNode;
						$refNode = $refElement->userData;
					} else {
						$parent = $refElement->userData;
						$refNode = null;
					}
					// https://html.spec.whatwg.org/#insert-a-character
					// If the adjusted insertion location is in a Document node, then
					// return.
					if ( $parent === $this->doc ) {
						return;
					}
					$data = substr( $text, $start, $length );
					// If there is a Text node immediately before the adjusted insertion
					// location, then append data to that Text node's data.
					if ( $refNode === null ) {
						$prev = $parent->getLastChild();
					} else {
						/** @var Node $refNode */
						$prev = $refNode->getPreviousSibling();
					}
					if ( $prev !== null && $prev->getNodeType() === XML_TEXT_NODE ) {
						'@phan-var CharacterData $prev'; /** @var CharacterData $prev */
						$prev->appendData( $data );
					} else {
						$node = $this->doc->createTextNode( $data );
						$parent->insertBefore( $node, $refNode );
					}
				}
		};
		$treeBuilder = new TreeBuilder( $domBuilder, [
			'ignoreErrors' => true
		] );
		$dispatcher = new Dispatcher( $treeBuilder );
		$tokenizer = new Tokenizer( $dispatcher, $string, [
			'ignoreErrors' => true ]
		);
		$tokenizer->execute( [] );

		// For compatibility with PHP's DOMDocument::loadHTML() -- if we didn't
		// see an actual <head> element during the parse, remove the head;
		// and if we didn't see an actual <body> during the parse, remove it.
		if ( $options['phpCompat'] ?? false ) {
			$head = $doc->getHead();
			if (
				( !$domBuilder->sawRealHead ) && $head && $head->_empty()
			) {
				$head->remove();
			}
			$body = $doc->getBody();
			if (
				( !$domBuilder->sawRealBody ) && $body && $body->_empty()
			) {
				$body->remove();
			}
		}

		$result = $domBuilder->getFragment();
		// @phan-suppress-next-line PhanTypeMismatchReturnSuperType
		return $result;
	}

	/**
	 * An XML parser ... is a construct that follows the rules given in
	 * XML to map a string of bytes or characters into a Document
	 * object.
	 *
	 * The spec then follows that up with:
	 * "Note: At the time of writing, no such rules actually exist."
	 *
	 * Use the enabled-by-default PHP XMLReader class to do our
	 * parsing and cram it into a Document somehow, and hope we don't
	 * mangle things too badly.
	 *
	 * @see https://html.spec.whatwg.org/multipage/xhtml.html#xml-parser
	 *
	 * @param Node $node A node to which to append the parsed XML
	 * @param string $s The string to parse
	 * @param array $options
	 * @internal
	 */
	public static function _parseXml( Node $node, string $s, array $options ): void {
		# The XMLReader class is cranky about empty strings.
		if ( $s === '' ) {
			throw new BadXMLException( "no root element found" );
		}
		$reader = new XMLReader();
		$reader->XML(
			$s, 'utf-8',
			LIBXML_NOERROR | LIBXML_NONET | LIBXML_NOWARNING | LIBXML_PARSEHUGE
		);
		$doc = $node->_nodeDocument;
		$attrNode = null;
		while ( $reader->moveToNextAttribute() || $reader->read() ) {
			switch ( $reader->nodeType ) {
			case XMLReader::END_ELEMENT:
				$node = $node->getParentNode();
				// Workaround to prevent us from visiting the attributes again
				while ( $reader->moveToNextAttribute() ) {
					/* skip */
				}
				break;
			case XMLReader::ELEMENT:
				$qname = $reader->prefix ?? '';
				if ( $qname !== '' ) {
					$qname .= ':';
				}
				$qname .= $reader->localName;
				// This will be the node we'll attach attributes to!
				$attrNode = $doc->createElementNS( $reader->namespaceURI, $qname );
				if ( $options['skipRoot'] ?? false ) {
					$options['skipRoot'] = false;
					break;
				}
				$node->appendChild( $attrNode );
				// We don't get an END_ELEMENT from the reader if this is
				// an empty element (sigh)
				if ( !$reader->isEmptyElement ) {
					$node = $attrNode;
				}
				break;
			case XMLReader::ATTRIBUTE:
				$qname = $reader->prefix ?? '';
				if ( $qname !== '' ) {
					$qname .= ':';
				}
				$qname .= $reader->localName;
				'@phan-var Element $attrNode';
				$attrNode->setAttributeNS(
					$reader->namespaceURI, $qname, $reader->value
				);
				break;
			case XMLReader::SIGNIFICANT_WHITESPACE:
			case XMLReader::TEXT:
				$nn = $doc->createTextNode( $reader->value );
				$node->appendChild( $nn );
				break;
			case XMLReader::CDATA:
				$nn = $doc->createCDATASection( $reader->value );
				$node->appendChild( $nn );
				break;
			case XMLReader::COMMENT:
				$nn = $doc->createComment( $reader->value );
				$node->appendChild( $nn );
				break;
			case XMLReader::DOC_TYPE:
				# This is a hack: the PHP XMLReader interface provides no
				# way to extract the contents of a DOC_TYPE node!  So we're
				# going to give it to the HTML tokenizer to interpret.
				$tokenHandler = new class extends NullTokenHandler {
					/** @var string */
					public $name;
					/** @var string */
					public $publicId;
					/** @var string */
					public $systemId;

					/** @inheritDoc */
					public function doctype(
						$name, $publicId, $systemId,
						$quirks, $sourceStart, $sourceLength
					) {
						$this->name = $name;
						$this->publicId = $publicId;
						$this->systemId = $systemId;
					}
				};
				( new Tokenizer(
					$tokenHandler, $reader->readOuterXml(), []
				) )->execute( [] );
				$nn = $doc->getImplementation()->createDocumentType(
					$tokenHandler->name ?? '',
					$tokenHandler->publicId ?? '',
					$tokenHandler->systemId ?? ''
				);
				$node->appendChild( $nn );
				break;
			default:
				throw new BadXMLException( "Unknown node type: " . $reader->nodeType );
			}
		}
	}
}
