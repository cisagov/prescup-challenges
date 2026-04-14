<?php

declare( strict_types = 1 );
// phpcs:disable MediaWiki.Commenting.FunctionComment.MissingDocumentationPublic
// phpcs:disable MediaWiki.Commenting.FunctionComment.WrongStyle
// phpcs:disable MediaWiki.Commenting.PropertyDocumentation.MissingDocumentationPublic
// phpcs:disable MediaWiki.NamingConventions.LowerCamelFunctionsName.FunctionName
// phpcs:disable PSR2.Methods.MethodDeclaration.Underscore

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\UnimplementedTrait;

/**
 * The Window is not a particularly relevant interface for our
 * use case of building and manipulating a document quickly.
 * We will, afaik, not need any of the interfaces provided here,
 * since we are operating in a somewhat "headless" mode.
 *
 * Consider eliminating this, or stubbing it.
 * @phan-forbid-undeclared-magic-properties
 */
class Window extends EventTarget implements \Wikimedia\IDLeDOM\Window {
	// DOM mixins
	use GlobalEventHandlers;
	use WindowEventHandlers;

	// Stub out methods not yet implements.
	use \Wikimedia\IDLeDOM\Stub\Window;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Window;

	public $document;
	public $console = null;
	public $history = null;
	public $navigator = null;

	/**
	 * @param Document|null $doc
	 */
	public function __construct( Document $doc = null ) {
		if ( $doc == null ) {
			$doc = new Document();
			$doc->_setContentType( 'text/html', true );
		}

		$this->document = $doc;
		/*
		  $this->document->_scripting_enabled = true;
		  $this->document->defaultView = $this;

		  if ( !$this->document->_address ) {
		  $this->document->_address = "about:blank";
		  }

		  // Instantiate sub-objects
		  $this->location = new Location( $this, $this->document->_address );
		  $this->console = new Console(); // not implemented
		  $this->history = new History(); // not implemented
		  $this->navigator = new NavigatorID();

		  // Self-referential properties; moved from prototype in port
		  $this->window = $this;
		  $this->self = $this;
		  $this->frames = $this;

		  // Self-referential properties for a top-level window
		  $this->parent = $this;
		  $this->top = $this;

		  // We don't support any other windows for now
		  $this->length = 0;              // no frames
		  $this->frameElement = null;     // not part of a frame
		  $this->opener = null;           // not opened by another window
		*/
	}

	public function _run( $code, $file ) {
		/* Original JS: */
		/*
		 * This was used only for the testharness, I think we
		 * will have another way to do this here.
		 */
		/*
		  if ($file) {
		  $code += '\n//@ sourceURL=' + $file;
		  }
		  with($this) eval($code);
		*/
	}

	/*
	 * The onload event handler.
	 * TODO: Need to support a bunch of other event types, too, and have
	 * them interoperate with document.body.
	 */
	public function onload( $handler = null ) {
		/*
		if ( $handler == null ) {
			// From the EventTarget parent class
			return $this->_getEventHandler( "load" );
		} else {
			return $this->_setEventHandler( "load", $handler );
		}
		*/
	}
}
