<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;

class HTMLElement extends Element implements \Wikimedia\IDLeDOM\HTMLElement {
	// DOM mixins
	use DocumentAndElementEventHandlers;
	use ElementCSSInlineStyle;
	use ElementContentEditable;
	use GlobalEventHandlers;
	use HTMLOrSVGElement;

	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\HTMLElement;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\HTMLElement;

	/**
	 * HTML Element constructor
	 *
	 * @param Document $doc
	 * @param string $lname
	 * @param ?string $prefix
	 * @return void
	 */
	public function __construct( Document $doc, string $lname, ?string $prefix = null ) {
		parent::__construct( $doc, $lname, Util::NAMESPACE_HTML, $prefix );
	}

	/**
	 * Create the appropriate "element interface" for an HTML element.
	 * @see https://html.spec.whatwg.org/#elements-in-the-dom:element-interface
	 * @param Document $doc
	 * @param string $lname
	 * @param ?string $prefix
	 * @return HTMLElement
	 */
	public static function _createElement( Document $doc, string $lname, ?string $prefix = null ) {
		$className = self::_lookupClass( $lname );
		return new $className( $doc, $lname, $prefix );
	}

	/**
	 * @param string $lname
	 * @return class-string
	 */
	private static function _lookupClass( string $lname ): string {
		switch ( $lname ) {
		case 'applet':
		case 'bgsound':
		case 'blink':
		case 'isindex':
		case 'keygen':
		case 'multicol':
		case 'nextid':
		case 'spacer':
			return HTMLUnknownElement::class;
		case 'acronym':
		case 'basefont':
		case 'big':
		case 'center':
		case 'nobr':
		case 'noembed':
		case 'noframes':
		case 'plaintext':
		case 'rb':
		case 'rtc':
		case 'strike':
		case 'tt':
			return self::class;
		case 'listing':
		case 'xmp':
			return HTMLPreElement::class;
		// "Otherwise, if this specification defines an interface appropriate
		// for the element type corresponding to the local name, return that
		// interface."
		case 'a':
			return HTMLAnchorElement::class;
		case 'abbr':
		case 'address':
			return self::class;
		case 'area':
			return HTMLAreaElement::class;
		case 'article':
		case 'aside':
			return self::class;
		case 'audio':
			return HTMLAudioElement::class;
		case 'b':
			return self::class;
		case 'base':
			return HTMLBaseElement::class;
		case 'bdi':
		case 'bdo':
			return self::class;
		case 'blockquote':
			return HTMLQuoteElement::class;
		case 'body':
			return HTMLBodyElement::class;
		case 'br':
			return HTMLBRElement::class;
		case 'button':
			return HTMLButtonElement::class;
		case 'canvas':
			return HTMLCanvasElement::class;
		case 'caption':
			return HTMLTableCaptionElement::class;
		case 'cite':
		case 'code':
			return self::class;
		case 'col':
			return HTMLTableColElement::class;
		case 'colgroup':
			return HTMLTableColElement::class;
		case 'data':
			return HTMLDataElement::class;
		case 'datalist':
			return HTMLDataListElement::class;
		case 'dd':
			return self::class;
		case 'del':
			return HTMLModElement::class;
		case 'details':
			return HTMLDetailsElement::class;
		case 'dfn':
			return self::class;
		case 'dialog':
			return HTMLDialogElement::class;
		case 'div':
			return HTMLDivElement::class;
		case 'dl':
			return HTMLDListElement::class;
		case 'dt':
		case 'em':
			return self::class;
		case 'embed':
			return HTMLEmbedElement::class;
		case 'fieldset':
			return HTMLFieldSetElement::class;
		case 'figcaption':
		case 'figure':
		case 'footer':
			return self::class;
		case 'form':
			return HTMLFormElement::class;
		case 'h1':
		case 'h2':
		case 'h3':
		case 'h4':
		case 'h5':
		case 'h6':
			return HTMLHeadingElement::class;
		case 'head':
			return HTMLHeadElement::class;
		case 'header':
		case 'hgroup':
			return self::class;
		case 'hr':
			return HTMLHRElement::class;
		case 'html':
			return HTMLHtmlElement::class;
		case 'i':
			return self::class;
		case 'iframe':
			return HTMLIFrameElement::class;
		case 'img':
			return HTMLImageElement::class;
		case 'input':
			return HTMLInputElement::class;
		case 'ins':
			return HTMLModElement::class;
		case 'kbd':
			return self::class;
		case 'label':
			return HTMLLabelElement::class;
		case 'legend':
			return HTMLLegendElement::class;
		case 'li':
			return HTMLLIElement::class;
		case 'link':
			return HTMLLinkElement::class;
		case 'main':
			return self::class;
		case 'map':
			return HTMLMapElement::class;
		case 'mark':
			return self::class;
		case 'menu':
			return HTMLMenuElement::class;
		case 'meta':
			return HTMLMetaElement::class;
		case 'meter':
			return HTMLMeterElement::class;
		case 'nav':
		case 'noscript':
			return self::class;
		case 'object':
			return HTMLObjectElement::class;
		case 'ol':
			return HTMLOListElement::class;
		case 'optgroup':
			return HTMLOptGroupElement::class;
		case 'option':
			return HTMLOptionElement::class;
		case 'output':
			return HTMLOutputElement::class;
		case 'p':
			return HTMLParagraphElement::class;
		case 'param':
			return HTMLParamElement::class;
		case 'picture':
			return HTMLPictureElement::class;
		case 'pre':
			return HTMLPreElement::class;
		case 'progress':
			return HTMLProgressElement::class;
		case 'q':
			return HTMLQuoteElement::class;
		case 'rp':
		case 'rt':
		case 'ruby':
		case 's':
		case 'samp':
			return self::class;
		case 'script':
			return HTMLScriptElement::class;
		case 'section':
			return self::class;
		case 'select':
			return HTMLSelectElement::class;
		case 'slot':
			return HTMLSlotElement::class;
		case 'small':
			return self::class;
		case 'source':
			return HTMLSourceElement::class;
		case 'span':
			return HTMLSpanElement::class;
		case 'strong':
			return self::class;
		case 'style':
			return HTMLStyleElement::class;
		case 'sub':
		case 'summary':
		case 'sup':
			return self::class;
		case 'table':
			return HTMLTableElement::class;
		case 'tbody':
			return HTMLTableSectionElement::class;
		case 'td':
			return HTMLTableCellElement::class;
		case 'template':
			return HTMLTemplateElement::class;
		case 'textarea':
			return HTMLTextAreaElement::class;
		case 'tfoot':
			return HTMLTableSectionElement::class;
		case 'th':
			return HTMLTableCellElement::class;
		case 'thead':
			return HTMLTableSectionElement::class;
		case 'time':
			return HTMLTimeElement::class;
		case 'title':
			return HTMLTitleElement::class;
		case 'tr':
			return HTMLTableRowElement::class;
		case 'track':
			return HTMLTrackElement::class;
		case 'u':
			return self::class;
		case 'ul':
			return HTMLUListElement::class;
		case 'var':
			return self::class;
		case 'video':
			return HTMLVideoElement::class;
		case 'wbr':
			return self::class;
		default:
			// In theory we'd test here to see if this was a "valid custom
			// element name", but we don't support custom elements (yet).
			return HTMLUnknownElement::class;
		}
	}
}
