<?php

declare( strict_types = 1 );
// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.MethodDoubleUnderscore
// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.ScopeNotCamelCaps

namespace Wikimedia\Dodo;

use Wikimedia\Dodo\Internal\NamespacePrefixMap;
use Wikimedia\Dodo\Internal\UnimplementedException;
use Wikimedia\Dodo\Internal\UnimplementedTrait;
use Wikimedia\Dodo\Internal\Util;
use Wikimedia\Dodo\Internal\WhatWG;
use Wikimedia\IDLeDOM\ChildNode as IChildNode;
use Wikimedia\IDLeDOM\GetRootNodeOptions;
use Wikimedia\IDLeDOM\Node as INode;

/**
 * Node.php
 * --------
 * Defines a "Node", the primary datatype of the W3C Document Object Model.
 *
 * Conforms to W3C Document Object Model (DOM) Level 1 Recommendation
 * (see: https://www.w3.org/TR/2000/WD-DOM-Level-1-20000929)
 * @phan-forbid-undeclared-magic-properties
 */
abstract class Node extends EventTarget implements \Wikimedia\IDLeDOM\Node {
	// Stub out methods not yet implemented.
	use \Wikimedia\IDLeDOM\Stub\Node;
	use UnimplementedTrait;

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\Node;

	/**********************************************************************
	 * Abstract methods that must be defined in subclasses
	 */

	/**
	 * Delegated subclass method called by Node::isEqualNode()
	 * @param Node $node
	 * @return bool
	 */
	abstract protected function _subclassIsEqualNode( Node $node ): bool;

	/**
	 * Delegated subclass method called by Node::cloneNode()
	 * @return Node
	 */
	abstract protected function _subclassCloneNodeShallow(): Node;

	/**********************************************************************
	 * Properties that appear in DOM-LS
	 */

	/**
	 * The document this node is associated to.
	 *
	 * spec DOM-LS
	 *
	 * NOTE
	 * This is different from ownerDocument: According to DOM-LS,
	 * Document::ownerDocument() must equal NULL, even though it's often
	 * more convenient if a document is its own owner.
	 *
	 * What we're looking for is the "node document" concept, as laid
	 * out in the DOM-LS spec:
	 *
	 *      -"Each node has an associated node document, set upon creation,
	 *       that is a document."
	 *
	 *      -"A node's node document can be changed by the 'adopt'
	 *       algorithm."
	 *
	 *      -"The node document of a document is that document itself."
	 *
	 *      -"All nodes have a node document at all times."
	 *
	 * NOTE
	 * The DOM-LS method Node::getRootNode (and the "root" of a node) is
	 * not the same thing: the root of a node which hasn't been added to
	 * the document is the highest ancestor; while the node document is
	 * always the owning document even if this node hasn't yet been
	 * added to it.
	 *
	 * @var Document
	 */
	public $_nodeDocument;

	/**
	 * @var Node|null should be considered read-only
	 */
	public $_parentNode;

	/**
	 * The sibling list is stored as a circular linked list: the node "before"
	 * the first sibling is the last sibling, and the node "after" the last
	 * sibling is the first sibling.  This makes finding the last sibling
	 * as quick as finding the first.
	 *
	 * As a consequence, if a Node has no siblings, i.e. it is the 'only child'
	 * of $_parentNode, then the properties $_nextSibling and $_previousSibling
	 * are set equal to $this (ie, a single-element circular list).
	 *
	 * Obviously, the DOM LS accessors return 'null' at the beginning and
	 * ends of the list (as well as for both siblings when the node is
	 * an only child); we tweak the getters to make this work.
	 *
	 * But be very careful when you access `_nextSibling` directly! If you
	 * want a null-terminated list, use `getNextSibling()` instead!
	 *
	 * @var Node
	 */
	public $_nextSibling;

	/**
	 * @see $_nextSibling
	 * @var Node
	 */
	public $_previousSibling;

	/**********************************************************************
	 * Properties that are for internal use by this library
	 */

	/**
	 * DEVELOPERS NOTE:
	 * An index is assigned when a node is added to a Document (becomes
	 * rooted). It uniquely identifies the Node within its owner Document.
	 *
	 * This index makes it simple to represent a Node as an integer.
	 *
	 * This is also used to determine if a Node is currently rooted.
	 *
	 * It allows this optimization: If two Elements have the same id,
	 * they will be stored in an array under their $document_index. This
	 * means we don't have to search the array for a matching Node when
	 * another node with the same ID is added or removed from the document;
	 * we can do a look up in O(1).  If your document contains lots of
	 * elements with identical IDs, this prevents a quadratic slowdown.
	 *
	 * @var ?int
	 */
	public $_documentIndex = null;

	/**
	 * DEVELOPERS NOTE:
	 * An index is assigned on INSERTION. It uniquely identifies the Node among
	 * its siblings.
	 *
	 * It is used to help compute document position and to mark where insertion should
	 * occur.
	 *
	 * Its existence is, frankly, mostly for convenience due to the fact that the most
	 * common representation of child nodes is a linked list that doesn't have numeric
	 * indices otherwise.
	 *
	 * FIXME It is public because it gets used by the whatwg algorithms page.
	 * @var ?int
	 */
	public $_cachedSiblingIndex = null;

	/**
	 * Create a Node whose node document is the given $nodeDocument.
	 * @param Document $nodeDocument
	 */
	public function __construct( Document $nodeDocument ) {
		/* Our ancestors */
		$this->_nodeDocument = $nodeDocument;
		$this->_parentNode = null;

		/* Our siblings */
		$this->_nextSibling = $this; // note: circular linked list
		$this->_previousSibling = $this; // note: circular linked list
	}

	/**********************************************************************
	 * ACCESSORS
	 */

	/*
	 * Sometimes, subclasses will override
	 * nodeValue and textContent, so these
	 * accessors should be seen as "defaults,"
	 * which in some cases are extended.
	 */

	/**
	 * Return the node type enumeration for this node.
	 * @see https://dom.spec.whatwg.org/#dom-node-nodetype
	 * @return int
	 */
	abstract public function getNodeType(): int;

	/**
	 * Return the `nodeName` for this node.
	 * @see https://dom.spec.whatwg.org/#dom-node-nodename
	 * @return string
	 */
	abstract public function getNodeName(): string;

	/**
	 * Return the `value` for this node.
	 * @see https://dom.spec.whatwg.org/#dom-node-nodevalue
	 * @return ?string
	 */
	public function getNodeValue(): ?string {
		return null; // Override in subclasses
	}

	/** @inheritDoc */
	public function setNodeValue( ?string $val ): void {
		/* Any other node: Do nothing */
	}

	/**
	 * Return the `textContent` for this node.
	 * @see https://dom.spec.whatwg.org/#dom-node-textcontent
	 * @return ?string
	 */
	public function getTextContent(): ?string {
		return null; // Override in subclasses
	}

	/** @inheritDoc */
	public function setTextContent( ?string $val ): void {
		/* Any other node: Do nothing */
	}

	/**
	 * The ownerDocument getter steps are to return null, if this is a
	 * document; otherwise this’s node document.
	 *
	 * We will override this implementation to return null
	 * in the Document class.
	 *
	 * @inheritDoc
	 */
	public function getOwnerDocument(): ?Document {
		return $this->_nodeDocument;
	}

	/**
	 * Nodes might not have a parentNode. Perhaps they have not been inserted
	 * into a DOM, or are a Document node, which is the root of a DOM tree and
	 * thus has no parent. In those cases, the value of parentNode is null.
	 *
	 * @return ?Node
	 */
	final public function getParentNode() {
		return $this->_parentNode;
	}

	/**
	 * This value is the same as parentNode, except it puts an extra condition,
	 * that the parentNode must be an Element.
	 *
	 * Accordingly, it requires no additional backing property, and can exist only
	 * as an accessor.
	 *
	 * @inheritDoc
	 */
	final public function getParentElement(): ?Element {
		if ( $this->_parentNode === null ) {
			return null;
		}
		if ( $this->_parentNode->getNodeType() === self::ELEMENT_NODE ) {
			// @phan-suppress-next-line PhanTypeMismatchReturn
			return $this->_parentNode;
		}
		return null;
	}

	/**
	 * Return this' shadow-including root if options['composed'] is true;
	 * otherwise return this' root.  NOTE that the root of a node
	 * is not (necessarily) the ownerDocument or node document
	 * of the node!
	 * @see https://dom.spec.whatwg.org/#dom-node-getrootnode
	 * @see https://dom.spec.whatwg.org/#concept-tree-root
	 * @param GetRootNodeOptions|associative-array|null $options
	 * @return \Wikimedia\IDLeDOM\Node
	 */
	public function getRootNode( /* ?mixed */ $options = null ) {
		$composed = false;
		if ( $options !== null ) {
			$options = GetRootNodeOptions::cast( $options );
			$composed = $options->getComposed();
		}
		if ( $composed ) {
			throw new UnimplementedException( __METHOD__ . ' (composed)' );
		}
		$root = $this;
		while ( $root->getParentNode() !== null ) {
			$root = $root->getParentNode();
			'@phan-var Node $root'; // guaranteed to be non-null
		}
		return $root;
	}

	/** @inheritDoc */
	final public function getPreviousSibling(): ?Node {
		if ( $this->_parentNode === null ) {
			return null;
		}
		if ( $this->_parentNode->getFirstChild() === $this ) {
			// Remember that previousSibling is a circular linked list,
			// so if this is the "first child" then we *should* return null
			// here (but _previousSibling will actually point to the "last
			// child" in this case).
			return null;
		}
		return $this->_previousSibling;
	}

	/** @inheritDoc */
	final public function getNextSibling(): ?Node {
		if ( $this->_parentNode === null ) {
			return null;
		}
		if ( $this->_nextSibling === $this->_parentNode->getFirstChild() ) {
			// Remember that nextSibling is a circular linked list,
			// so if our next sibling is the "first child" then we *should*
			// return null here (but _nextSibling will actually point back
			// to the start of the list in this case).
			return null;
		}
		return $this->_nextSibling;
	}

	/**
	 * This should be overridden in ContainerNode and Leaf.
	 * @inheritDoc
	 */
	abstract public function getChildNodes(): NodeList;

	/**
	 * This should be overridden in ContainerNode and Leaf.
	 * @inheritDoc
	 */
	abstract public function getFirstChild(): ?Node;

	/**
	 * This should be overridden in ContainerNode and Leaf.
	 * @inheritDoc
	 */
	abstract public function getLastChild(): ?Node;

	/**
	 * <script> elements need to know when they're inserted into the
	 * document.  See Document::_root(Node).  Override this method
	 * to invoke such a hook.
	 */
	public function _roothook() {
		/* do nothing by default */
	}

	/**********************************************************************
	 * MUTATION ALGORITHMS
	 */

	/**
	 * Insert $node as a child of $this, and insert it before $refChild
	 * in the document order.
	 *
	 * spec DOM-LS
	 *
	 * THINGS TO KNOW FROM THE SPEC:
	 *
	 * 1. If $node already exists in
	 *    this Document, this function
	 *    moves it from its current
	 *    position to its new position
	 *    ('move' means 'remove' followed
	 *    by 're-insert').
	 *
	 * 2. If $refNode is NULL, then $node
	 *    is added to the end of the list
	 *    of children of $this. In other
	 *    words, insertBefore($node, NULL)
	 *    is equivalent to appendChild($node).
	 *
	 * 3. If $node is a DocumentFragment,
	 *    the children of the DocumentFragment
	 *    are moved into the child list of
	 *    $this, and the empty DocumentFragment
	 *    is returned.
	 *
	 * THINGS TO KNOW IN LIFE:
	 *
	 * Despite its weird syntax (blame the spec),
	 * this is a real workhorse, used to implement
	 * all of the non-replacing insertion mutations.
	 *
	 * @param INode $node To be inserted
	 * @param ?INode $refNode Child of this node before which to insert $node
	 * @return Node Newly inserted Node or empty DocumentFragment
	 * @throws DOMException "HierarchyRequestError" or "NotFoundError"
	 */
	public function insertBefore(
		// phpcs:ignore MediaWiki.Commenting.FunctionComment.PHP71NullableDocOptionalArg
		$node, $refNode = null
	): Node {
		'@phan-var Node $node'; // @var Node $node
		'@phan-var ?Node $refNode'; // @var ?Node $refNode
		/*
		 * [1]
		 * Ensure pre-insertion validity.
		 * Validation failure will throw
		 * DOMException "HierarchyRequestError" or
		 * DOMException "NotFoundError".
		 */
		WhatWG::ensure_insert_valid( $node, $this, $refNode );
		'@phan-var Document|DocumentFragment|Element $this';

		/*
		 * [2]
		 * If $refNode is $node, re-assign
		 * $refNode to the next sibling of
		 * $node. This may well be NULL.
		 */
		if ( $refNode === $node ) {
			$refNode = $node->getNextSibling();
		}

		/*
		 * [3]
		 * Adopt $node into the Document
		 * to which $this is rooted.
		 */
		$this->_nodeDocument->adoptNode( $node );

		/*
		 * [4]
		 * Run the complicated algorithm
		 * to Insert $node into $this at
		 * a position before $refNode.
		 */
		WhatWG::insert_before_or_replace( $node, $this, $refNode, false );

		/*
		 * [5]
		 * Return $node
		 */
		return $node;
	}

	/** @inheritDoc */
	public function appendChild( $node ) {
		return $this->insertBefore( $node, null );
	}

	/**
	 * Does not check for insertion validity. This out-performs PHP DOMDocument by
	 * over 2x.
	 *
	 * @param Node $node
	 * @return Node
	 */
	public function _unsafeAppendChild( Node $node ): Node {
		'@phan-var ContainerNode $this';
		WhatWG::insert_before_or_replace( $node, $this, null, false );
		return $node;
	}

	/** @inheritDoc */
	public function replaceChild( $new, $old ): Node {
		'@phan-var Node $new'; // @var Node $new
		'@phan-var Node $old'; // @var Node $old
		/*
		 * [1]
		 * Ensure pre-replacement validity.
		 * Validation failure will throw
		 * DOMException "HierarchyRequestError" or
		 * DOMException "NotFoundError".
		 */
		WhatWG::ensure_replace_valid( $new, $this, $old );
		'@phan-var Document|DocumentFragment|Element $this';

		/*
		 * [2]
		 * Adopt $node into the Document
		 * to which $this is rooted.
		 */
		if ( $new->_nodeDocument !== $this->_nodeDocument ) {
			/*
			 * FIXME
			 * adoptNode has a side-effect
			 * of removing the adopted node
			 * from its parent, which
			 * generates a mutation event,
			 * causing _insertOrReplace to
			 * generate 2 deletes and 1 insert
			 * instead of a 'move' event.
			 *
			 * It looks like the MutationObserver
			 * stuff avoids this problem, but for
			 * now let's only adopt (ie, remove
			 * 'node' from its parent) here if we
			 * need to.
			 */
			$this->_nodeDocument->adoptNode( $new );
		}

		/*
		 * [4]
		 * Run the complicated algorithm
		 * to replace $old with $new.
		 */
		WhatWG::insert_before_or_replace( $new, $this, $old, true );

		/*
		 * [5]
		 * Return $old
		 */
		return $old;
	}

	/** @inheritDoc */
	public function removeChild( $node ): Node {
		if ( $this === $node->getParentNode() ) {
			/* Defined on ChildNode class */
			'@phan-var IChildNode $node'; // @var IChildNode $node
			$node->remove();
		} else {
			/* That's not my child! */
			Util::error( "NotFoundError" );
		}
		/*
		 * The spec requires that
		 * the return value always
		 * be equal to $node.
		 */
		// @phan-suppress-next-line PhanTypeMismatchReturn
		return $node;
	}

	/**
	 * Puts $this and the entire subtree
	 * rooted at $this into "normalized"
	 * form.
	 *
	 * In a normalized sub-tree, no text
	 * nodes in the sub-tree are empty,
	 * and there are no adjacent text nodes.
	 *
	 * @see https://dom.spec.whatwg.org/#dom-node-normalize
	 * @inheritDoc
	 */
	final public function normalize(): void {
		for ( $n = $this->getFirstChild(); $n !== null; $n = $next ) {
			// $n might get removed, so save the next sibling that we'll visit
			$next = $n->getNextSibling();

			/*
			 * [0]
			 * Proceed to traverse the
			 * subtree in a depth-first
			 * fashion.
			 */
			$n->normalize();

			if ( $n->getNodeType() === self::TEXT_NODE ) {
				'@phan-var Text $n'; // @var Text $n
				if ( $n->getNodeValue() === '' ) {
					/*
					 * [1]
					 * If you are a text node,
					 * and you are empty, then
					 * you get pruned.
					 */
					$this->removeChild( $n );
				} else {
					$p = $n->getPreviousSibling();
					if ( $p && $p->getNodeType() === self::TEXT_NODE ) {
						'@phan-var Text $p'; // @var Text $p
						/*
						 * [2]
						 * If you are a text node,
						 * and you are not empty,
						 * and you follow a
						 * non-empty text node
						 * (if it were empty, it
						 * would have been pruned
						 * in the depth-first
						 * traversal), then you
						 * get merged into that
						 * previous non-empty text
						 * node.
						 */
						$p->appendData( $n->getNodeValue() ?? '' );
						$this->removeChild( $n );
					}
				}
			}
		}
	}

	/**********************************************************************
	 * COMPARISONS AND PREDICATES
	 */

	/** @inheritDoc */
	final public function compareDocumentPosition( $that ): int {
		'@phan-var Node $that'; // @var Node $that
		/*
		 * CAUTION
		 * These arguments seem backwards, but that's how the
		 * specification defines it.
		 * https://dom.spec.whatwg.org/#dom-node-comparedocumentposition
		 */
		return WhatWG::compare_document_position( $that, $this );
	}

	/** @inheritDoc */
	final public function contains( $node ): bool {
		if ( $node === null ) {
			return false;
		}
		if ( $this === $node ) {
			/* As per the DOM-LS, containment is inclusive. */
			return true;
		}

		return ( $this->compareDocumentPosition( $node ) & self::DOCUMENT_POSITION_CONTAINED_BY ) !== 0;
	}

	/**
	 * @inheritDoc
	 */
	final public function isSameNode( $node ): bool {
		return $this === $node;
	}

	/**
	 * Determine whether this node and $other are equal
	 *
	 * spec: DOM-LS
	 *
	 * NOTE:
	 * Each subclass of Node has its own criteria for equality.
	 * Rather than extend   Node::isEqualNode(),  subclasses
	 * must implement   _subclassIsEqualNode(),  which is called
	 * from   Node::isEqualNode()  and handles all of the equality
	 * testing specific to the subclass.
	 *
	 * This allows the recursion and other fast checks to be
	 * handled here and written just once.
	 *
	 * Yes, we realize it's a bit weird.
	 *
	 * @inheritDoc
	 */
	public function isEqualNode( $node ): bool {
		if ( $node === null ) {
			/* We're not equal to NULL */
			return false;
		}
		if ( $node->getNodeType() !== $this->getNodeType() ) {
			/* If we're not the same nodeType, we can stop */
			return false;
		}

		if ( !( $node instanceof Node ) ) {
			// Not even the same implementation!
			// (This is really a hint to phan)
			return false;
		}
		if ( !$this->_subclassIsEqualNode( $node ) ) {
			/* Run subclass-specific equality comparison */
			return false;
		}

		/* Call this method on the children of both nodes */
		for (
			$a = $this->getFirstChild(), $b = $node->getFirstChild();
			$a !== null && $b !== null;
			$a = $a->getNextSibling(), $b = $b->getNextSibling()
		) {
			if ( !$a->isEqualNode( $b ) ) {
				return false;
			}
		}

		/* Verify that both lists of children were the same size */
		return $a === null && $b === null;
	}

	/**
	 * Clone this Node
	 *
	 * spec DOM-LS
	 *
	 * NOTE:
	 * 1. If $deep is false, then no child nodes are cloned, including
	 *    any text the node contains (since these are Text nodes).
	 * 2. The duplicate returned by this method is not part of any
	 *    document until it is added using ::appendChild() or similar.
	 * 3. Initially (DOM4)   , $deep was optional with default of 'true'.
	 *    Currently (DOM4-LS), $deep is optional with default of 'false'.
	 * 4. Shallow cloning is delegated to   _subclassCloneNodeShallow(),
	 *    which needs to be implemented by the subclass.
	 *    For a similar pattern, see Node::isEqualNode().
	 * 5. All "deep clones" are a shallow clone followed by recursion on
	 *    the tree structure, so this suffices to capture subclass-specific
	 *    behavior.
	 *
	 * @param bool $deep if true, clone entire subtree
	 * @return Node (clone of $this)
	 */
	public function cloneNode( bool $deep = false ): Node {
		/* Make a shallow clone using the delegated method */
		$clone = $this->_subclassCloneNodeShallow();

		/* If the shallow clone is all we wanted, we're done. */
		if ( !$deep ) {
			return $clone;
		}

		/* Otherwise, recurse on the children */
		for ( $n = $this->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
			$clone->_unsafeAppendChild( $n->cloneNode( true ) );
		}

		return $clone;
	}

	/**
	 * Return DOMString containing prefix for given namespace URI.
	 *
	 * spec DOM-LS
	 *
	 * NOTE
	 * Think this function looks weird? It's actually spec:
	 * https://dom.spec.whatwg.org/#locate-a-namespace
	 *
	 * @inheritDoc
	 */
	public function lookupPrefix( ?string $ns ): ?string {
		return WhatWG::locate_prefix( $this, $ns );
	}

	/**
	 * Return DOMString containing namespace URI for a given prefix
	 *
	 * NOTE
	 * Inverse of Node::lookupPrefix
	 *
	 * @inheritDoc
	 */
	public function lookupNamespaceURI( ?string $prefix ): ?string {
		if ( $prefix === '' ) {
			$prefix = null;
		}
		return WhatWG::locate_namespace( $this, $prefix );
	}

	/**
	 * Determine whether this is the default namespace
	 *
	 * @inheritDoc
	 */
	public function isDefaultNamespace( ?string $ns ): bool {
		if ( $ns === '' ) {
			$ns = null;
		}
		return $ns === $this->lookupNamespaceURI( null );
	}

	/*
	 * UTILITY METHODS AND DODO EXTENSIONS
	 */

	/**
	 * Get an XPath for a node.
	 * This is a PHP-compatibility extension to the DOM spec.
	 * @return ?string
	 */
	public function getNodePath() {
		if ( !$this->getIsConnected() ) {
			return null;
		}
		$parent = $this->getParentNode();
		if ( $parent === null ) {
			return '';
		}
		$name = Util::toAsciiLowercase( $this->getNodeName() );
		$count = 0;
		$idx = 0;
		for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
			if (
				$n->getNodeType() === $this->getNodeType() &&
				Util::toAsciiLowercase( $n->getNodeName() ) === $name
			) {
				$count++;
			}
			if ( $n === $this ) {
				$idx = $count;
			}
		}
		$s = $parent->getNodePath() . '/' . $name;
		if ( $count > 1 ) {
			$s .= '[' . $idx . ']';
		}
		return $s;
	}

	/**
	 * Set the ownerDocument reference on a subtree rooted at $this.
	 *
	 * Called by Document::adoptNode()
	 *
	 * @param Document $doc
	 */
	public function _resetNodeDocument( Document $doc ) {
		$this->_nodeDocument = $doc;

		// NOTE that the value returned by ::getNodeName() and ::getTagName()
		// can change after this node is adopted into a new document.  If
		// we'd cached those values we'd need to invalidate that cache here.

		for ( $n = $this->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
			$n->_resetNodeDocument( $doc );
		}
	}

	/**
	 * Determine whether this Node is rooted (belongs to the tree rooted
	 * at the node document).
	 *
	 * @return bool
	 *
	 * NOTE
	 * Document nodes maintain a list of all the
	 * nodes inside their tree, assigning each an index,
	 * Node::_documentIndex.
	 *
	 * Therefore if we are currently rooted, we can tell by checking that
	 * we have one of these.
	 */
	public function getIsConnected(): bool {
		return $this->_documentIndex !== null;
	}

	/**
	 * The index of this Node in its parent's childNodes list
	 * @see https://dom.spec.whatwg.org/#concept-tree-index
	 *
	 * @return int index
	 * @throws \Throwable if we have no parent
	 *
	 * NOTE
	 * Calling Node::_getSiblingIndex() will automatically trigger a switch
	 * to the NodeList representation (see Node::childNodes()).
	 */
	public function _getSiblingIndex(): int {
		Util::assert( $this->_parentNode !== null );

		if ( $this === $this->_parentNode->getFirstChild() ) {
			return 0; // fast case
		}

		/* We fire up the NodeList mode */
		$childNodes = $this->_parentNode->getChildNodes();

		/* We end up re-indexing here if we ever run into trouble */
		if ( $this->_cachedSiblingIndex === null || $childNodes[$this->_cachedSiblingIndex] !== $this ) {
			/*
			 * Ensure that we don't have an O(N^2) blowup
			 * if none of the kids have defined indices yet
			 * and we're traversing via nextSibling or
			 * previousSibling
			 */
			foreach ( $childNodes as $i => $child ) {
				// @phan-suppress-next-line PhanUndeclaredProperty
				$child->_cachedSiblingIndex = $i;
			}

			Util::assert( $childNodes[$this->_cachedSiblingIndex] === $this );
		}
		return $this->_cachedSiblingIndex;
	}

	/**
	 * Return the lastModTime value for this node. (For use as a
	 * cache invalidation mechanism. If the node does not already
	 * have one, initialize it from the owner document's modclock
	 * property. (Note that modclock does not return the actual
	 * time; it is simply a counter incremented on each document
	 * modification.)
	 * @return int
	 */
	public function _lastModTime(): int {
		// In domino we'd first consult the per-node counter and return that
		// if present.  But we're saving space in our Nodes by keeping only
		// the document-level modclock.
		return $this->_nodeDocument->_modclock;
	}

	/**
	 * Increment the owner document's modclock [and use the new
	 * value to update the lastModTime value for this node and
	 * all of its ancestors. Nodes that have never had their
	 * lastModTime value queried do not need to have a
	 * lastModTime property set on them since there is no
	 * previously queried value to ever compare the new value
	 * against, so only update nodes that already have a
	 * _lastModTime property.]
	 */
	public function _modify(): void {
		$this->_nodeDocument->_modclock++;
		// In domino, we keep a per-node modification counter as well,
		// and we would now set the per-node counter to the document
		// modclock and walk up the ancestor tree setting each parent's
		// per-node counter.  This lets us distinguish modifications
		// which occur in separate subtrees.  In dodo we're going to
		// simplify and maintain only the document-level modification
		// counter.  If we need to we can always implement domino's
		// per-node counters here later, at the cost of extra storage
		// space in every node.
	}

	/**
	 * Remove all of the Node's children.
	 *
	 * NOTE
	 * Provides minor optimization over iterative calls to
	 * Node::removeChild(), since it calls Node::_modify() once.
	 */
	public function _removeChildren() {
		if ( !$this->hasChildNodes() ) {
			return;
		}
		// XXX: consider moving this code to ContainerNode?
		'@phan-var ContainerNode $this'; /** @var ContainerNode $this */
		if ( $this->getIsConnected() ) {
			$root = $this->_nodeDocument;
		} else {
			$root = null;
		}

		/* Go through all the children and remove me as their parent */
		for ( $n = $this->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
			if ( $root !== null ) {
				/* If we're rooted, mutate */
				$root->_mutateRemove( $n );
			}
			$n->_parentNode = null;
		}

		/* Remove the child node memory or references on this node */
		$this->_childNodes = null;
		$this->_firstChild = null;
		$this->_modify(); // Update last modified time once only
	}

	/**
	 * Convert the children of a node to an HTML string.
	 * This is effectively 'innerHTML' for nodes in HTML documents.
	 * This is overridden in specific children, in particular
	 * HTMLTemplateElement.
	 *
	 * @see https://html.spec.whatwg.org/#html-fragment-serialisation-algorithm
	 * @param string[] &$result The result is accumulated here
	 * @param array $options Format options passed to WhatWG::htmlSerialize
	 */
	public function _htmlSerialize( array &$result, array $options ): void {
		for ( $n = $this->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
			WhatWG::htmlSerialize( $result, $n, $this, $options );
		}
	}

	/**
	 * XML serialize the given node.  This is overridden in subclasses.
	 * Note that this is effectively "outerHTML", due to a spec
	 * inconsistency: https://github.com/w3c/DOM-Parsing/issues/28 .
	 *
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-xml-serialization
	 * @param ?string $namespace
	 * @param NamespacePrefixMap $prefixMap
	 * @param int &$prefixIndex
	 * @param array $options
	 * @param string[] &$markup accumulator for the result
	 */
	public function _xmlSerialize(
		?string $namespace, NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	): void {
		throw new TypeError( "can't serialize to XML" );
	}

	/**
	 * @see https://dom.spec.whatwg.org/#concept-node-length
	 * @return int The length of this node.
	 */
	abstract public function _length(): int;

	/**
	 * @see https://dom.spec.whatwg.org/#concept-node-empty
	 * @return bool Whether this node is considered empty.
	 */
	abstract public function _empty(): bool;

	// -------------------------------------------------------------

	// The next few functions define a standard "extension point" to
	// allow you to hang your own data off a node.  It uses dynamic
	// properties so no extra space is allocated for the Node object
	// unless/until you attach data.

	private const EXTENSION_PREFIX = '_extension_';

	/** @inheritDoc */
	protected function _setMissingProp( string $name, $value ): void {
		if ( substr_compare( $name, self::EXTENSION_PREFIX, 0, strlen( self::EXTENSION_PREFIX ) ) == 0 ) {
			$this->{$name} = $value;
			return;
		}
		parent::_setMissingProp( $name, $value );
	}

	/** @inheritDoc */
	protected function _getMissingProp( string $name ) {
		if ( substr_compare( $name, self::EXTENSION_PREFIX, 0, strlen( self::EXTENSION_PREFIX ) ) == 0 ) {
			return $this->{$name};
		}
		return parent::_getMissingProp( $name );
	}

	/**
	 * Get "extension data" associate with this node, using the given $key.
	 * @param string $key Distinguishes between various types of extension data.
	 * @param mixed $defaultValue The value to return if the extension data is
	 *   not present on this node; defaults to `null`.
	 * @return mixed The extension data associated with $key on this node.
	 */
	public function getExtensionData( string $key, $defaultValue = null ) {
		// Prefix the key to ensure it doesn't conflict with existing Dodo
		// private properties/
		$key = self::EXTENSION_PREFIX . $key;
		if ( !property_exists( $this, $key ) ) {
			return $defaultValue; // don't allocate in this case
		}
		return $this->{$key};
	}

	/**
	 * Set "extension data" associate with this node, using the given $key.
	 * @param string $key Distinguishes between various types of extension data.
	 * @param mixed $value The value to store under this $key on this node.
	 */
	public function setExtensionData( string $key, $value ) {
		// Prefix the key to ensure it doesn't conflict with existing Dodo
		// private properties/
		$key = self::EXTENSION_PREFIX . $key;
		$this->{$key} = $value;
	}
}
