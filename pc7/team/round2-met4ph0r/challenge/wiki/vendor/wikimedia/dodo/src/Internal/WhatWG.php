<?php

declare( strict_types = 1 );
// phpcs:disable Generic.Files.LineLength.TooLong
// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.ScopeNotCamelCaps

namespace Wikimedia\Dodo\Internal;

use Wikimedia\Dodo\Attr;
use Wikimedia\Dodo\Comment;
use Wikimedia\Dodo\ContainerNode;
use Wikimedia\Dodo\Document;
use Wikimedia\Dodo\DocumentFragment;
use Wikimedia\Dodo\DocumentType;
use Wikimedia\Dodo\DOMException;
use Wikimedia\Dodo\Element;
use Wikimedia\Dodo\HTMLTemplateElement;
use Wikimedia\Dodo\NamedNodeMap;
use Wikimedia\Dodo\Node;
use Wikimedia\Dodo\ProcessingInstruction;
use Wikimedia\Dodo\Text;
use Wikimedia\IDLeDOM\ChildNode as IChildNode;

/******************************************************************************
 * whatwg.php
 * ----------
 * Contains lots of broken-out implementations of algorithms
 * described in WHATWG and other specifications.
 *
 * It was broken out so that the methods in the various classes
 * could be simpler, and to allow for re-use in other places.
 *
 * It also makes it easier to read and understand in isolation from
 * the context of a class, where there can be many conveniences that
 * affect the implementation.
 *
 * That said, it may be a problem having so much on this one page,
 * so perhaps we need to re-examine things.
 *
 */
class WhatWG {

	/******************************************************************************
	 * TREE PREDICATES AND MUTATION
	 */

	/**
	 * @see https://dom.spec.whatwg.org/#dom-node-comparedocumentposition
	 * @param Node $node1
	 * @param Node $node2
	 * @return int
	 */
	public static function compare_document_position( Node $node1, Node $node2 ): int {
		/* #1-#2 */
		if ( $node1 === $node2 ) {
			return 0;
		}

		/* #3 */
		$attr1 = null;
		$attr2 = null;

		/* #4 */
		if ( $node1->getNodeType() === Node::ATTRIBUTE_NODE ) {
			'@phan-var Attr $node1'; // @var Attr $node1
			$attr1 = $node1;
			$node1 = $attr1->getOwnerElement();
		}
		/* #5 */
		if ( $node2->getNodeType() === Node::ATTRIBUTE_NODE ) {
			'@phan-var Attr $node2'; // @var Attr $node2
			$attr2 = $node2;
			$node2 = $attr2->getOwnerElement();

			if ( $attr1 !== null && $node1 !== null && $node2 === $node1 ) {
				foreach ( $node2->getAttributes() as $a ) {
					if ( $a === $attr1 ) {
						return Node::DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC + Node::DOCUMENT_POSITION_PRECEDING;
					}
					if ( $a === $attr2 ) {
						return Node::DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC + Node::DOCUMENT_POSITION_FOLLOWING;
					}
				}
			}
		}

		/* #6 */
		if ( $node1 === null || $node2 === null || $node1->getRootNode() !== $node2->getRootNode() ) {
			/* In the spec this is supposed to add
			* DOCUMENT_POSITION_PRECEDING or
			* DOCUMENT_POSITION_FOLLOWING in some consistent way,
			* "usually based on pointer comparison". Great.  Domino
			* just straight up omits it, but that causes us to fail
			* WPT tests.  Use spl_object_hash() to give us a
			* "consistent" (but arbitrary) ordering, as the spec
			* requests.
			 */
			$a = spl_object_hash( $node1 === null ? $attr1 : $node1 );
			$b = spl_object_hash( $node2 === null ? $attr2 : $node2 );
			$arbitrary = ( $a < $b ) ?
				Node::DOCUMENT_POSITION_PRECEDING :
				Node::DOCUMENT_POSITION_FOLLOWING;
			return (
				Node::DOCUMENT_POSITION_DISCONNECTED +
				Node::DOCUMENT_POSITION_IMPLEMENTATION_SPECIFIC +
				$arbitrary
			);
		}

		/* #7 */
		$node1_ancestors = [];
		$node2_ancestors = [];
		for ( $n = $node1->getParentNode(); $n !== null; $n = $n->getParentNode() ) {
			$node1_ancestors[] = $n;
		}
		for ( $n = $node2->getParentNode(); $n !== null; $n = $n->getParentNode() ) {
			$node2_ancestors[] = $n;
		}

		if ( in_array( $node1, $node2_ancestors, true ) && $attr1 === null ) {
			return Node::DOCUMENT_POSITION_CONTAINS + Node::DOCUMENT_POSITION_PRECEDING;
		} elseif ( $node1 === $node2 && $attr2 !== null ) {
			return Node::DOCUMENT_POSITION_CONTAINS + Node::DOCUMENT_POSITION_PRECEDING;
		}

		/* #8 */
		if ( in_array( $node2, $node1_ancestors, true ) && $attr2 === null ) {
			return Node::DOCUMENT_POSITION_CONTAINED_BY + Node::DOCUMENT_POSITION_FOLLOWING;
		} elseif ( $node1 === $node2 && $attr1 !== null ) {
			return Node::DOCUMENT_POSITION_CONTAINED_BY + Node::DOCUMENT_POSITION_FOLLOWING;
		}

		/* #9 */
		$node1_ancestors = array_reverse( $node1_ancestors );
		$node2_ancestors = array_reverse( $node2_ancestors );
		// Make these "inclusive" ancestor lists
		$node1_ancestors[] = $node1;
		$node2_ancestors[] = $node2;
		$len = min( count( $node1_ancestors ), count( $node2_ancestors ) );
		'@phan-var Node[] $node1_ancestors'; // @var Node[] $node1_ancestors
		'@phan-var Node[] $node2_ancestors'; // @var Node[] $node2_ancestors

		for ( $i = 1; $i < $len; $i++ ) {
			if ( $node1_ancestors[$i] !== $node2_ancestors[$i] ) {
				// We found two different ancestors, so compare their positions
				// (By definition they must share the same parent)
				if ( $node1_ancestors[$i]->_getSiblingIndex() < $node2_ancestors[$i]->_getSiblingIndex() ) {
					return Node::DOCUMENT_POSITION_PRECEDING;
				} else {
					return Node::DOCUMENT_POSITION_FOLLOWING;
				}
			}
		}
		// If we get to here, then one of the nodes (the one with the
		// shorter list of ancestors) contains the other one.
		// But that should have been caught in step #8!
		throw new \Exception( "should be unreachable" );
	}

	/*
	 * DOM-LS Removes the 'prefix' and 'namespaceURI' attributes from
	 * Node and places them only on Element and Attr.
	 *
	 * Due to the fact that an Attr (should) have an ownerElement,
	 * these two algorithms only operate on Elements.
	 *
	 * The spec actually says that if an Attr has no ownerElement,
	 * then the algorithm returns NULL.
	 *
	 * Anyway, they operate only on Elements.
	 */

	/**
	 * @see https://dom.spec.whatwg.org/#locate-a-namespace
	 *
	 * @param Node $node
	 * @param ?string $prefix
	 * @return ?string
	 */
	public static function locate_namespace( Node $node, ?string $prefix ): ?string {
		if ( $prefix === '' ) {
			$prefix = null;
		}

		switch ( $node->getNodeType() ) {
		case Node::ENTITY_NODE:
		case Node::NOTATION_NODE:
		case Node::DOCUMENT_TYPE_NODE:
		case Node::DOCUMENT_FRAGMENT_NODE:
			return null;

		case Node::ELEMENT_NODE:
			'@phan-var Element $node'; // @var Element $node
			if ( $node->getNamespaceURI() !== null && $node->getPrefix() === $prefix ) {
				return $node->getNamespaceURI();
			}
			foreach ( $node->getAttributes() as $a ) {
				if ( $a->getNamespaceURI() === Util::NAMESPACE_XMLNS ) {
					if ( ( $a->getPrefix() === 'xmlns' && $a->getLocalName() === $prefix )
						 || ( $prefix === null && $a->getPrefix() === null && $a->getLocalName() === 'xmlns' ) ) {
						$val = $a->getValue();
						return ( $val === "" ) ? null : $val;
					}
				}
			}
			// fall through
		default:
			$parent = $node->getParentElement();
			if ( $parent === null ) {
				return null;
			} else {
				return self::locate_namespace( $parent, $prefix );
			}

		case Node::DOCUMENT_NODE:
			'@phan-var Document $node'; // @var Document $node
			$el = $node->getDocumentElement();
			return ( $el === null ) ? null :
				self::locate_namespace( $el, $prefix );

		case Node::ATTRIBUTE_NODE:
			'@phan-var Attr $node'; // @var Attr $node
			$el = $node->getOwnerElement();
			return ( $el === null ) ? null :
				self::locate_namespace( $el, $prefix );
		}
	}

	/**
	 * @see https://dom.spec.whatwg.org/#locate-a-namespace-prefix
	 *
	 * @param Node $node
	 * @param ?string $ns
	 * @return ?string
	 */
	public static function locate_prefix( Node $node, ?string $ns ): ?string {
		if ( $ns === "" || $ns === null ) {
			return null;
		}

		switch ( $node->getNodeType() ) {
		case Node::ENTITY_NODE:
		case Node::NOTATION_NODE:
		case Node::DOCUMENT_FRAGMENT_NODE:
		case Node::DOCUMENT_TYPE_NODE:
			return null;

		case Node::ELEMENT_NODE:
			'@phan-var Element $node'; // @var Element $node
			if ( $node->getNamespaceURI() === $ns ) {
				return $node->getPrefix();
			}

			foreach ( $node->getAttributes() as $a ) {
				if ( $a->getPrefix() === "xmlns" && $a->getValue() === $ns ) {
					return $a->getLocalName();
				}
			}
			// fall through
		default:
			$parent = $node->getParentElement();
			if ( $parent === null ) {
				return null;
			} else {
				'@phan-var Element $parent'; // @var Element $parent
				return self::locate_prefix( $parent, $ns );
			}

		case Node::DOCUMENT_NODE:
			'@phan-var Document $node'; // @var Document $node
			$el = $node->getDocumentElement();
			return ( $el === null ) ? null :
				self::locate_prefix( $el, $ns );

		case Node::ATTRIBUTE_NODE:
			'@phan-var Attr $node'; // @var Attr $node
			$el = $node->getOwnerElement();
			return ( $el === null ) ? null :
				self::locate_prefix( $el, $ns );
		}
	}

	/**
	 * @param Node $child
	 * @param ContainerNode $parent
	 * @param ?Node $before
	 * @param bool $replace
	 */
	public static function insert_before_or_replace( Node $child, ContainerNode $parent, ?Node $before, bool $replace ): void {
		/*
		 * TODO: FACTOR: $before is intended to always be non-NULL
		 * if $replace is true, but I think that could fail unless
		 * we encode it into the prototype, which is non-standard.
		 * (we are combining the 'insert before' and 'replace' algos)
		 */

		/******************* PRE-FLIGHT CHECKS */

		if ( $child instanceof DocumentFragment && $child->getIsConnected() ) {
			Util::error( "HierarchyRequestError" );
		}

		/* Ensure index of `before` is cached before we (possibly) remove it. */

		// phan can't tell that $ref_index is non-null iff childNodes is
		// non-null, so we'll set it here regardless.
		$ref_index = -1;
		if ( $parent->_childNodes !== null ) {
			if ( $before !== null ) {
				// save this index
				$ref_index = $before->_getSiblingIndex();
			} else {
				// phan can't tell that we've already tested $parent->_childNodes
				// and know that it is non-null:
				// @phan-suppress-next-line PhanTypeMismatchArgumentNullableInternal
				$ref_index = count( $parent->_childNodes );
			}
			// If we are already a child of the specified parent, then the
			// index may have to be adjusted
			if ( $child->_parentNode === $parent ) {
				$child_index = $child->_getSiblingIndex();
				// If the child is before the spot it is to be inserted at,
				// then when it is removed, the index of that spot will be
				// reduced
				if ( $child_index < $ref_index ) {
					$ref_index--;
				}
			}
		}

		// Delete the old child

		if ( $replace ) {
			Util::assert( $before !== null );
			if ( $before->getIsConnected() ) {
				$before->_nodeDocument->_mutateRemove( $before );
			}
			$before->_parentNode = null;
		}

		$ref_node = $before ?? $parent->getFirstChild();
		'@phan-var Node $ref_node'; // @var Node $ref_node

		// If both the child and the parent are rooted, then we want to
		// transplant the child without uprooting and rerooting it.

		$bothWereRooted = $child->getIsConnected() && $parent->getIsConnected();
		if ( $child instanceof DocumentFragment ) {
			$insert = [];
			for ( $n = $child->getFirstChild(); $n !== null; $n = $next ) {
				$next = $n->getNextSibling();
				$insert[] = $n;
				$n->_parentNode = $parent;
			}
			$len = count( $insert );
			if ( $replace ) {
				LinkedList::ll_replace(
					$ref_node, $len > 0 ? $insert[0] : null
				);
			} elseif ( $len > 0 && $ref_node !== null ) {
				LinkedList::ll_insert_before(
					$insert[0], $ref_node
				);
			}
			if ( $parent->_childNodes !== null ) {
				$firstIndex = ( $before === null ) ?
					// phan can't tell that we've already tested
					// $parent->_childNodes and know that it is non-null:
					// @phan-suppress-next-line PhanTypeMismatchArgumentNullableInternal
					count( $parent->_childNodes ) :
					$before->_cachedSiblingIndex;
				$parent->_childNodes->_splice(
					$firstIndex,
					$replace ? 1 : 0,
					$insert
				);
				foreach ( $insert as $i => $ni ) {
					$ni->_cachedSiblingIndex = $firstIndex + $i;
				}
			} elseif ( $parent->_firstChild === $before ) {
				if ( count( $insert ) > 0 ) {
					$parent->_firstChild = $insert[0];
				} elseif ( $replace ) {
					$parent->_firstChild = null;
				}
			}
			// Remove all nodes from the document fragment
			if ( $child->_childNodes !== null ) {
				$child->_childNodes->_splice(
					0, $child->_childNodes->getLength()
				);
			} else {
				$child->_firstChild = null;
			}
			// Call the mutation handlers
			// Use $insert since the original array has been destroyed. The
			// liveness guarantee requires us to clone the array so that
			// references to the childNodes of the DocumentFragment will be empty
			// when the insertion handlers are called.
			if ( $parent->getIsConnected() ) {
				$parent->_modify();
				foreach ( $insert as $i => $ni ) {
					$parent->_nodeDocument->_mutateInsert( $ni );
				}
			}
		} else { // Not a DocumentFragment
			if ( $before === $child ) {
				return;
			}

			if ( $bothWereRooted ) {
				/* "soft remove" -- don't want to uproot it. */
				// Remove the child from its current position in the tree
				// without calling remove(), since we don't want to uproot it.
				// @phan-suppress-next-line PhanUndeclaredMethod in ChildNode trait
				$child->_remove();
			} elseif ( $child->_parentNode ) {
				'@phan-var IChildNode $child'; // @var IChildNode $child
				$child->remove();
			}

			// Insert it as a child of its new parent
			$child->_parentNode = $parent;
			if ( $replace ) {
				LinkedList::ll_replace( $ref_node, $child );
				if ( $parent->_childNodes !== null ) {
					$child->_cachedSiblingIndex = $ref_index;
					$parent->_childNodes->_set( $ref_index, $child );
				} elseif ( $parent->_firstChild === $before ) {
					$parent->_firstChild = $child;
				}
			} else {
				if ( $ref_node !== null ) {
					LinkedList::ll_insert_before( $child, $ref_node );
				}
				if ( $parent->_childNodes !== null ) {
					$child->_cachedSiblingIndex = $ref_index;
					$parent->_childNodes->_splice( $ref_index, 0, [ $child ] );
				} elseif ( $parent->_firstChild === $before ) {
					$parent->_firstChild = $child;
				}
			}
			if ( $bothWereRooted ) {
				$parent->_modify();
				// Generate a move mutation event
				$parent->_nodeDocument->_mutateMove( $child );
			} elseif ( $parent->getIsConnected() ) {
				$parent->_modify();
				// Generate an insertion mutation event
				$parent->_nodeDocument->_mutateInsert( $child );
			}
		}
	}

	/**
	 * TODO: Look at the way these were implemented in the original;
	 * there are some speedups esp in the way that you implement
	 * things like "node has a doctype child that is not child
	 *
	 * @param Node $node
	 * @param Node $parent
	 * @param ?Node $child
	 */
	public static function ensure_insert_valid( Node $node, Node $parent, ?Node $child ): void {
		/*
		 * DOM-LS: #1: If parent is not a Document, DocumentFragment,
		 * or Element node, throw a HierarchyRequestError.
		 */
		switch ( $parent->getNodeType() ) {
		case Node::DOCUMENT_NODE:
		case Node::DOCUMENT_FRAGMENT_NODE:
		case Node::ELEMENT_NODE:
			break;
		default:
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #2: If node is a host-including inclusive ancestor
		 * of parent, throw a HierarchyRequestError.
		 */
		if ( $node === $parent ) {
			Util::error( "HierarchyRequestError" );
		}
		if ( $node->_nodeDocument === $parent->_nodeDocument && $node->getIsConnected() === $parent->getIsConnected() ) {
			/*
			 * If the conditions didn't figure it out, then check
			 * by traversing parentNode chain.
			 */
			for ( $n = $parent; $n !== null; $n = $n->getParentNode() ) {
				if ( $n === $node ) {
					Util::error( "HierarchyRequestError" );
				}
			}
		}

		/*
		 * DOM-LS #3: If child is not null and its parent is not $parent, then
		 * throw a NotFoundError
		 */
		if ( $child !== null && $child->_parentNode !== $parent ) {
			Util::error( "NotFoundError" );
		}

		/*
		 * DOM-LS #4: If node is not a DocumentFragment, DocumentType,
		 * Element, Text, ProcessingInstruction, or Comment Node,
		 * throw a HierarchyRequestError.
		 */
		switch ( $node->getNodeType() ) {
		case Node::DOCUMENT_FRAGMENT_NODE:
		case Node::DOCUMENT_TYPE_NODE:
		case Node::ELEMENT_NODE:
		case Node::TEXT_NODE:
		case Node::CDATA_SECTION_NODE: // also a Text node
		case Node::PROCESSING_INSTRUCTION_NODE:
		case Node::COMMENT_NODE:
			break;
		default:
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #5. If either:
		 *      -node is a Text and parent is a Document
		 *          (CDATA counts as a Text node)
		 *      -node is a DocumentType and parent is not a Document
		 * throw a HierarchyRequestError
		 */
		if ( ( ( $node->getNodeType() === Node::TEXT_NODE || $node->getNodeType() === Node::CDATA_SECTION_NODE ) && $parent->getNodeType() === Node::DOCUMENT_NODE )
			 || ( $node->getNodeType() === Node::DOCUMENT_TYPE_NODE && $parent->getNodeType() !== Node::DOCUMENT_NODE ) ) {
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #6: If parent is a Document, and any of the
		 * statements below, switched on node, are true, throw a
		 * HierarchyRequestError.
		 */
		if ( $parent->getNodeType() !== Node::DOCUMENT_NODE ) {
			return;
		}

		switch ( $node->getNodeType() ) {
		case Node::DOCUMENT_FRAGMENT_NODE:
			/*
			 * DOM-LS #6a-1: If node has more than one
			 * Element child or has a Text child.
			 */
			$count_text = 0;
			$count_element = 0;

			for ( $n = $node->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::TEXT_NODE || $n->getNodeType() === Node::CDATA_SECTION_NODE ) {
					$count_text++;
				}
				if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
					$count_element++;
				}
				if ( $count_text > 0 && $count_element > 1 ) {
					Util::error( "HierarchyRequestError" );
					// TODO: break ? return ?
				}
			}
			/*
			 * DOM-LS #6a-2: If node has one Element
			 * child and either:
			 */
			if ( $count_element === 1 ) {
				/* DOM-LS #6a-2a: child is a DocumentType */
				if ( $child !== null && $child->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
				/*
				 * DOM-LS #6a-2b: child is not NULL and a
				 * DocumentType is following child.
				 */
				if ( $child !== null ) {
					for ( $n = $child->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
						if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
							Util::error( "HierarchyRequestError" );
						}
					}
				}
				/* DOM-LS #6a-2c: parent has an Element child */
				for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
					if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
						Util::error( "HierarchyRequestError" );
					}
				}
			}
			break;
		case Node::ELEMENT_NODE:
			/* DOM-LS #6b-1: child is a DocumentType */
			if ( $child !== null && $child->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
				Util::error( "HierarchyRequestError" );
			}
			/* DOM-LS #6b-2: child not NULL and DocumentType is following child. */
			if ( $child !== null ) {
				for ( $n = $child->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
					if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
						Util::error( "HierarchyRequestError" );
					}
				}
			}
			/* DOM-LS #6b-3: parent has an Element child */
			for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			break;
		case Node::DOCUMENT_TYPE_NODE:
			/* DOM-LS #6c-1: parent has a DocumentType child */
			for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			/*
			 * DOM-LS #6c-2: child is not NULL and an Element
			 * is preceding child,
			 */
			if ( $child !== null ) {
				for ( $n = $child->getPreviousSibling(); $n !== null; $n = $n->getPreviousSibling() ) {
					if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
						Util::error( "HierarchyRequestError" );
					}
				}
			}
			/*
			 * DOM-LS #6c-3: child is NULL and parent has
			 * an Element child.
			 */
			if ( $child === null ) {
				for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
					if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
						Util::error( "HierarchyRequestError" );
					}
				}
			}

			break;
		}
	}

	/**
	 * @param Node $node
	 * @param Node $parent
	 * @param Node $child
	 */
	public static function ensure_replace_valid( Node $node, Node $parent, Node $child ): void {
		/*
		 * DOM-LS: #1: If parent is not a Document, DocumentFragment,
		 * or Element node, throw a HierarchyRequestError.
		 */
		switch ( $parent->getNodeType() ) {
		case Node::DOCUMENT_NODE:
		case Node::DOCUMENT_FRAGMENT_NODE:
		case Node::ELEMENT_NODE:
			break;
		default:
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #2: If node is a host-including inclusive ancestor
		 * of parent, throw a HierarchyRequestError.
		 */
		if ( $node === $parent ) {
			Util::error( "HierarchyRequestError" );
		}
		if ( $node->_nodeDocument === $parent->_nodeDocument && $node->getIsConnected() === $parent->getIsConnected() ) {
			/*
			 * If the conditions didn't figure it out, then check
			 * by traversing parentNode chain.
			 */
			for ( $n = $parent; $n !== null; $n = $n->getParentNode() ) {
				if ( $n === $node ) {
					Util::error( "HierarchyRequestError" );
				}
			}
		}

		/*
		 * DOM-LS #3: If child's parentNode is not parent
		 * throw a NotFoundError
		 */
		if ( $child->_parentNode !== $parent ) {
			Util::error( "NotFoundError" );
		}

		/*
		 * DOM-LS #4: If node is not a DocumentFragment, DocumentType,
		 * Element, Text, ProcessingInstruction, or Comment Node,
		 * throw a HierarchyRequestError.
		 */
		switch ( $node->getNodeType() ) {
		case Node::DOCUMENT_FRAGMENT_NODE:
		case Node::DOCUMENT_TYPE_NODE:
		case Node::ELEMENT_NODE:
		case Node::TEXT_NODE:
		case Node::CDATA_SECTION_NODE: // this is also a Text node
		case Node::PROCESSING_INSTRUCTION_NODE:
		case Node::COMMENT_NODE:
			break;
		default:
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #5. If either:
		 *      -node is a Text and parent is a Document
		 *          (CDATA counts as a Text node)
		 *      -node is a DocumentType and parent is not a Document
		 * throw a HierarchyRequestError
		 */
		if ( ( ( $node->getNodeType() === Node::TEXT_NODE || $node->getNodeType() === Node::CDATA_SECTION_NODE ) && $parent->getNodeType() === Node::DOCUMENT_NODE )
			 || ( $node->getNodeType() === Node::DOCUMENT_TYPE_NODE && $parent->getNodeType() !== Node::DOCUMENT_NODE ) ) {
			Util::error( "HierarchyRequestError" );
		}

		/*
		 * DOM-LS #6: If parent is a Document, and any of the
		 * statements below, switched on node, are true, throw a
		 * HierarchyRequestError.
		 */
		if ( $parent->getNodeType() !== Node::DOCUMENT_NODE ) {
			return;
		}

		switch ( $node->getNodeType() ) {
		case Node::DOCUMENT_FRAGMENT_NODE:
			/*
			 * #6a-1: If node has more than one Element child
			 * or has a Text child.
			 */
			$count_text = 0;
			$count_element = 0;

			for ( $n = $node->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::TEXT_NODE || $n->getNodeType() === Node::CDATA_SECTION_NODE ) {
					$count_text++;
				}
				if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
					$count_element++;
				}
				if ( $count_text > 0 && $count_element > 1 ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			/* #6a-2: If node has one Element child and either: */
			if ( $count_element === 1 ) {
				/* #6a-2a: parent has an Element child that is not child */
				for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
					if ( $n->getNodeType() === Node::ELEMENT_NODE && $n !== $child ) {
						Util::error( "HierarchyRequestError" );
					}
				}
				/* #6a-2b: a DocumentType is following child. */
				for ( $n = $child->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
					if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
						Util::error( "HierarchyRequestError" );
					}
				}
			}
			break;
		case Node::ELEMENT_NODE:
			/* #6b-1: parent has an Element child that is not child */
			for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::ELEMENT_NODE && $n !== $child ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			/* #6b-2: DocumentType is following child. */
			for ( $n = $child->getNextSibling(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			break;
		case Node::DOCUMENT_TYPE_NODE:
			/* #6c-1: parent has a DocumentType child */
			for ( $n = $parent->getFirstChild(); $n !== null; $n = $n->getNextSibling() ) {
				if ( $n->getNodeType() === Node::DOCUMENT_TYPE_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			/* #6c-2: an Element is preceding child */
			for ( $n = $child->getPreviousSibling(); $n !== null; $n = $n->getPreviousSibling() ) {
				if ( $n->getNodeType() === Node::ELEMENT_NODE ) {
					Util::error( "HierarchyRequestError" );
				}
			}
			break;
		}
	}

	/**
	 * Return the "descendant text content" of the given node.
	 * @see https://dom.spec.whatwg.org/#concept-descendant-text-content
	 * @param Node $node
	 * @param string[] &$bits the result is returned in this array
	 */
	public static function descendantTextContent( Node $node, array &$bits ): void {
		if ( $node instanceof \Wikimedia\IDLeDOM\Text ) {
			$bits[] = $node->getData();
		} else {
			for ( $kid = $node->getFirstChild(); $kid !== null; $kid = $kid->getNextSibling() ) {
				self::descendantTextContent( $kid, $bits );
			}
		}
	}

	/******************************************************************************
	 * SERIALIZATION
	 */

	/**
	 * PORT NOTES
	 *      The `serializeOne()` function used to live on the `Node.prototype`
	 *      as a private method `Node#_serializeOne(child)`, however that requires
	 *      a megamorphic property access `this._serializeOne` just to get to the
	 *      method, and this is being done on lots of different `Node` subclasses,
	 *      which puts a lot of pressure on V8's megamorphic stub cache. So by
	 *      moving the helper off of the `Node.prototype` and into a separate
	 *      function in this helper module, we get a monomorphic property access
	 *      `NodeUtils.serializeOne` to get to the function and reduce pressure
	 *      on the megamorphic stub cache.
	 *      See https://github.com/fgnass/domino/pull/142 for more information.
	 */
	/* http://www.whatwg.org/specs/web-apps/current-work/multipage/the-end.html#serializing-html-fragments */

	/** @var array<string,bool> */
	private static $hasRawContent = [
		"STYLE" => true,
		"SCRIPT" => true,
		"XMP" => true,
		"IFRAME" => true,
		"NOEMBED" => true,
		"NOFRAMES" => true,
		"PLAINTEXT" => true
	];

	/** @var array<string,bool> */
	private static $emptyElements = [
		"area" => true,
		"base" => true,
		"basefont" => true,
		"bgsound" => true,
		"br" => true,
		"col" => true,
		"embed" => true,
		"frame" => true,
		"hr" => true,
		"img" => true,
		"input" => true,
		"keygen" => true,
		"link" => true,
		"menuitem" => true,
		"meta" => true,
		"param" => true,
		"source" => true,
		"track" => true,
		"wbr" => true
	];

	/** @var array<string,bool> */
	private static $extraNewLine = [
		/* Removed in https://github.com/whatwg/html/issues/944 */
		/*
		  "pre" => true,
		  "textarea" => true,
		  "listing" => true
		*/
	];

	/**
	 * @param string $s
	 * @return string
	 */
	public static function _helper_escape( $s ) {
		return str_replace(
			/* PORT: PHP7: \u{00a0} */
			/*
			 * NOTE: '&'=>'&amp;' must come first! Processing done LTR,
			 * so otherwise we will recursively replace the &'s.
			 */
			[ "&","<",">","\u{00A0}" ],
			[ "&amp;", "&lt;", "&gt;", "&nbsp;" ],
			$s
		);
	}

	/**
	 * @param string $s
	 * @return string
	 */
	public static function _helper_escapeAttr( $s ) {
		return str_replace(
			[ "&", "\"", "\u{00A0}" ],
			[ "&amp;", "&quot;", "&nbsp;" ],
			$s
		);

		/* TODO: Is there still a fast path in PHP? (see NodeUtils.js) */
	}

	/**
	 * @param Attr $a
	 * @return string
	 */
	public static function _helper_attrname( Attr $a ) {
		$ns = $a->getNamespaceURI();

		if ( !$ns ) {
			return $a->getLocalName();
		}

		if ( $ns === Util::NAMESPACE_XML ) {
			return 'xml:' . $a->getLocalName();
		}
		if ( $ns === Util::NAMESPACE_XLINK ) {
			return 'xlink:' . $a->getLocalName();
		}
		if ( $ns === Util::NAMESPACE_XMLNS ) {
			if ( $a->getLocalName() === 'xmlns' ) {
				return 'xmlns';
			} else {
				return 'xmlns:' . $a->getLocalName();
			}
		}

		return $a->getName();
	}

	/**
	 * The "XML serialization" algorithm.
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-xml-serialization
	 * @param Node $node
	 * @param array $options
	 * @param string[] &$markup
	 */
	public static function xmlSerialize(
		Node $node, array $options, array &$markup
	): void {
		$contextNamespace = null;
		$prefixMap = new NamespacePrefixMap();
		$prefixMap->add( Util::NAMESPACE_XML, 'xml' );
		$prefixIndex = 1;
		if (
			( $options['phpCompat'] ?? false ) &&
			$node->_nodeDocument->_isHTMLDocument()
		) {
			$contextNamespace = Util::NAMESPACE_HTML;
		}
		try {
				$node->_xmlSerialize(
					$contextNamespace, $prefixMap, $prefixIndex,
					$options, $markup
				);
		} catch ( \Throwable $t ) {
			Util::error( 'InvalidStateError' );
		}
	}

	/**
	 * XML serializing an Element node.
	 * Moved here from Element::_xmlSerialize because it's huge!
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-xml-serializing-an-element-node
	 * @param Element $el
	 * @param ?string $namespace
	 * @param NamespacePrefixMap $prefixMap
	 * @param int &$prefixIndex
	 * @param array $options
	 * @param string[] &$markup accumulator for the result
	 */
	public static function xmlSerializeElement(
		Element $el, ?string $namespace,
		NamespacePrefixMap $prefixMap, int &$prefixIndex,
		array $options, array &$markup
	) {
		if ( $options['requireWellFormed'] ?? false ) {
			if (
				strpos( $el->getLocalName(), ':' ) !== false ||
				!self::is_valid_xml_name( $el->getLocalName() )
			) {
				throw new BadXMLException();
			}
		}
		$markup[] = '<';
		$qualifiedName = '';
		$ignoreNamespaceDefinitionAttribute = false;
		$map = $prefixMap->clone(); // new copy
		$localPrefixesMap = [];
		$localDefaultNamespace =
			$map->recordNamespaceInformation( $el, $localPrefixesMap );
		$inheritedNs = $namespace;
		$ns = $el->getNamespaceURI();
		if ( $inheritedNs === $ns ) {
			if ( $localDefaultNamespace !== null ) {
				$ignoreNamespaceDefinitionAttribute = true;
			}
			if ( $ns === Util::NAMESPACE_XML ) {
				$qualifiedName .= 'xml:';
			}
			$qualifiedName .= $el->getLocalName();
			$markup[] = $qualifiedName;
		} else {
			$prefix = $el->getPrefix();
			if ( $prefix === null && $ns === $localDefaultNamespace ) {
				// https://github.com/w3c/DOM-Parsing/issues/52
				$candidatePrefix = null;
			} else {
				$candidatePrefix = $map->retrievePreferredPrefix( $ns, $prefix );
			}
			if ( $prefix === 'xmlns' ) {
				if ( $options['requireWellFormed'] ?? false ) {
					throw new BadXMLException();
				}
				$candidatePrefix = $prefix;
			}
			// We've found a suitable namespace prefix
			if ( $candidatePrefix !== null ) {
				$qualifiedName .= $candidatePrefix . ':' . $el->getLocalName();
				if (
					$localDefaultNamespace !== null &&
					$localDefaultNamespace !== Util::NAMESPACE_XML
				) {
					$inheritedNs = $localDefaultNamespace;
					if ( $inheritedNs === '' ) {
						$inheritedNs = null;
					}
				}
				$markup[] = $qualifiedName;
			} elseif ( $prefix !== null ) {
				// Create a new namespace prefix declaration
				if ( array_key_exists( $prefix, $localPrefixesMap ) ) {
					$prefix = $map->generatePrefix( $ns, $prefixIndex );
				}
				$map->add( $ns, $prefix );
				$qualifiedName .= $prefix . ':' . $el->getLocalName();
				$markup[] = $qualifiedName;
				$markup[] = ' xmlns:' . $prefix . '="';
				self::xmlSerializeAttrValue( $ns, $options, $markup );
				$markup[] = '"';
				if ( $localDefaultNamespace !== null ) {
					$inheritedNs = $localDefaultNamespace;
					if ( $inheritedNs === '' ) {
						$inheritedNs = null;
					}
				}
			} elseif (
				$localDefaultNamespace === null ||
				// https://github.com/w3c/DOM-Parsing/issues/47
				$localDefaultNamespace !== ( $ns ?? '' )
			) {
				// The namespace still needs to be serialized, but there's
				// no prefix or candidate prefix available.  Use the default
				// namespace declaration to define the namespace.
				$ignoreNamespaceDefinitionAttribute = true;
				$qualifiedName .= $el->getLocalName();
				$inheritedNs = $ns;
				$markup[] = $qualifiedName;
				$markup[] = ' xmlns="';
				self::xmlSerializeAttrValue( $ns, $options, $markup );
				$markup[] = '"';
			} else {
				// The node has a local default namespace that matches ns
				$qualifiedName .= $el->getLocalName();
				$inheritedNs = $ns;
				$markup[] = $qualifiedName;
			}
		}
		// Serialize the attributes
		self::xmlSerializeAttributes(
			$el->getAttributes(), $map, $prefixIndex, $localPrefixesMap,
			$ignoreNamespaceDefinitionAttribute, $options,
			$markup
		);

		if (
			$ns === Util::NAMESPACE_HTML &&
			( !$el->hasChildNodes() ) &&
			( self::$emptyElements[$el->getLocalName()] ?? false ) &&
			!( $options['noEmptyTag'] ?? false )
		) {
			$markup[] = ' />';
			return;
		}
		if (
			$ns !== Util::NAMESPACE_HTML &&
			( !$el->hasChildNodes() ) &&
			!( $options['noEmptyTag'] ?? false )
		) {
			$markup[] = '/>';
			return;
		}
		$markup[] = '>';
		// handle the template element specially
		if (
			$ns === Util::NAMESPACE_HTML &&
			$el->getLocalName() === 'template'
		) {
			$templateContents = ( $el instanceof HTMLTemplateElement ) ?
				$el->getContent() :
				$el->getOwnerDocument()->createDocumentFragment();
			$templateContents->_xmlSerialize(
				$inheritedNs, $map, $prefixIndex, $options,
				$markup
			);
		} else {
			// handle element contents
			for ( $child = $el->getFirstChild(); $child !== null; $child = $child->getNextSibling() ) {
				$child->_xmlSerialize(
					$inheritedNs, $map, $prefixIndex, $options,
					$markup
				);
			}
		}
		// close the tag
		$markup[] = '</' . $qualifiedName . '>';
	}

	/**
	 * XML serialization of the attributes of an element.
	 * @see https://w3c.github.io/DOM-Parsing/#serializing-an-element-s-attributes
	 * @param NamedNodeMap $attributes
	 * @param NamespacePrefixMap $map
	 * @param int &$prefixIndex
	 * @param array<string,string> &$localPrefixesMap
	 * @param bool $ignoreNamespaceDefinitionAttribute
	 * @param array $options
	 * @param string[] &$markup accumulator for the result
	 */
	public static function xmlSerializeAttributes(
		NamedNodeMap $attributes, NamespacePrefixMap $map, int &$prefixIndex,
		array &$localPrefixesMap, bool $ignoreNamespaceDefinitionAttribute,
		array $options,
		array &$markup
	) {
		$localnameSet = [];
		foreach ( $attributes as $attr ) {
			if ( $options['requireWellFormed'] ?? false ) {
				$key = var_export(
					[ $attr->getNamespaceURI(), $attr->getLocalName() ],
					true
				);
				if ( $localnameSet[$key] ?? false ) {
					throw new BadXMLException();
				}
				$localnameSet[$key] = true;
			}
			$attrNs = $attr->getNamespaceURI();
			$candidatePrefix = null;
			if ( $attrNs !== null ) {
				$candidatePrefix = $map->retrievePreferredPrefix(
					$attrNs, $attr->getPrefix()
				);
				if ( $attrNs === Util::NAMESPACE_XMLNS ) {
					if ( $attr->getValue() === Util::NAMESPACE_XML ) {
						continue;
					}
					if ( $attr->getPrefix() === null ) {
						if (
							$ignoreNamespaceDefinitionAttribute &&
							// https://github.com/w3c/DOM-Parsing/issues/47
							// @phan-suppress-next-line PhanCoalescingNeverNullInLoop Phan says getValue never returns null
							( $attr->getValue() ?? '' ) !== ( $attr->getOwnerElement()->getNamespaceURI() ?? '' )
						) {
							continue;
						}
					} elseif (
						( !array_key_exists( $attr->getLocalName(), $localPrefixesMap ) ) ||
						$localPrefixesMap[$attr->getLocalName()] !== $attr->getValue()
					) {
						if ( $map->found( $attr->getValue(), $attr->getLocalName() ) ) {
							// the current namespace prefix definition was
							// exactly defined previously on an ancestor
							continue;
						}
					}
					if ( $options['requireWellFormed'] ?? false ) {
						if ( $attr->getValue() === Util::NAMESPACE_XMLNS ) {
							throw new BadXMLException();
						}
						if (
							// https://github.com/w3c/DOM-Parsing/issues/48
							$attr->getPrefix() !== null &&
							$attr->getValue() === ''
						) {
							throw new BadXMLException();
						}
					}
					if ( $attr->getPrefix() === 'xmlns' ) {
						$candidatePrefix = 'xmlns';
					}
				} elseif ( $candidatePrefix === null ) {
					// The above condition is not (yet) in the spec.
					// Firefox also tries to preserve the attributes
					// existing prefix (if any) in this case, which isn't
					// (yet?) reflected in the spec or the test case.
					// See discussion at
					// https://github.com/w3c/DOM-Parsing/issues/29

					// attribute namespace is not the XMLNS namespace
					$candidatePrefix = $map->generatePrefix(
						$attrNs, $prefixIndex
					);
					$markup[] = ' xmlns:' . $candidatePrefix . '="';
					self::xmlSerializeAttrValue(
						$attrNs, $options, $markup
					);
					$markup[] = '"';
				}
			}
			$markup[] = ' ';
			if ( $candidatePrefix !== null ) {
				$markup[] = $candidatePrefix . ':';
			}
			if ( $options['requireWellFormed'] ?? false ) {
				if (
					strpos( $attr->getLocalName(), ':' ) !== false ||
					( !self::is_valid_xml_name( $attr->getLocalName() ) ) ||
					( $attrNs === null && $attr->getLocalName() === 'xmlns' )
				) {
					throw new BadXMLException();
				}
			}
			$markup[] = $attr->getLocalName();
			$markup[] = '="';
			self::xmlSerializeAttrValue(
				$attr->getValue(), $options, $markup
			);
			$markup[] = '"';
		}
	}

	/**
	 * Serialize an attribute value (for XML).
	 * @see https://w3c.github.io/DOM-Parsing/#dfn-serializing-an-attribute-value
	 * @param ?string $value
	 * @param array $options
	 * @param string[] &$markup
	 */
	public static function xmlSerializeAttrValue(
		?string $value, array $options, array &$markup
	): void {
		if ( $value === null ) {
			return; // "The empty string"
		}
		if ( $options['requireWellFormed'] ?? false ) {
			if ( !self::is_valid_xml_chars( $value ) ) {
				throw new BadXMLException();
			}
		}
		$markup[] = strtr(
			$value,
			[
				'&' => '&amp;',
				'"' => '&quot;',
				'<' => '&lt;',
				'>' => '&gt;',
				// These aren't in the spec, but should be:
				// https://github.com/w3c/DOM-Parsing/issues/59
				"\t" => '&#x9;',
				"\n" => '&#xA;',
				"\r" => '&#xD;',
			]
		);
	}

	/**
	 * This is part of the "HTML fragment serialization algorithm".
	 * @see https://html.spec.whatwg.org/#html-fragment-serialisation-algorithm
	 * @param array<string> &$result
	 * @param Node $child
	 * @param ?Node $parent This is null when evaluating outerHtml
	 * @param array $options
	 */
	public static function htmlSerialize( array &$result, Node $child, ?Node $parent, array $options = [] ): void {
		switch ( $child->getNodeType() ) {
		case Node::ELEMENT_NODE:
			'@phan-var Element $child'; // @var Element $child
			$ns = $child->getNamespaceURI();
			$html = ( $ns === Util::NAMESPACE_HTML );

			if ( $html || $ns === Util::NAMESPACE_SVG || $ns === Util::NAMESPACE_MATHML ) {
				$tagname = $child->getLocalName();
			} else {
				$tagname = $child->getTagName();
			}

			$result[] = '<' . $tagname;

			foreach ( $child->getAttributes() as $a ) {
				// @phan-suppress-next-line PhanTypeMismatchArgumentSuperType
				$result[] = ' ' . self::_helper_attrname( $a );

				/*
				 * PORT: TODO: Need to ensure this value is NULL
				 * rather than undefined?
				 */
				// @phan-suppress-next-line PhanImpossibleTypeComparisonInLoop Phan says getValue never returns null
				if ( $a->getValue() !== null ) {
					$result[] = '="' . self::_helper_escapeAttr( $a->getValue() ) . '"';
				}
			}

			$result[] = '>';

			if ( !( $html && isset( self::$emptyElements[$tagname] ) ) ) {
				$i = count( $result );
				$result[] = ''; // save a space
				$child->_htmlSerialize( $result, $options );
				if ( $html && isset( self::$extraNewLine[$tagname] ) &&
					 ( $result[$i + 1][0] ?? '' ) === "\n" ) {
					$result[$i] = "\n"; // insert a newline
				}
				/* Serialize children and add end tag for all others */
				$result[] = '</' . $tagname . '>';
			}
			break;

		case Node::TEXT_NODE:
		case Node::CDATA_SECTION_NODE:
			'@phan-var Text $child'; // @var Text $child
			if (
				$parent &&
				$parent->getNodeType() === Node::ELEMENT_NODE &&
				$parent instanceof Element &&
				$parent->getNamespaceURI() === Util::NAMESPACE_HTML
			) {
				$parenttag = $parent->getTagName();
			} else {
				$parenttag = '';
			}

			if (
				( self::$hasRawContent[$parenttag] ?? false ) ||
				(
					$parenttag === 'NOSCRIPT' &&
					$parent->_nodeDocument->_scripting_enabled
				)
			) {
				$result[] = $child->getData();
			} else {
				$result[] = self::_helper_escape( $child->getData() );
			}
			break;

		case Node::COMMENT_NODE:
			'@phan-var Comment $child'; // @var Comment $child
			$result[] = '<!--' . $child->getData() . '-->';
			break;

		case Node::PROCESSING_INSTRUCTION_NODE:
			'@phan-var ProcessingInstruction $child'; // @var ProcessingInstruction $child
			$result[] = '<?' . $child->getTarget() . ' ' . $child->getData() . '?>';
			break;

		case Node::DOCUMENT_TYPE_NODE:
			// See
			// https://www.w3.org/TR/DOM-Parsing/#dfn-concept-serialize-doctype
			// BUT
			// https://html.spec.whatwg.org/multipage/parsing.html#serialising-html-fragments
			// omits the public/system ID.
			'@phan-var DocumentType $child'; // @var DocumentType $child
			$result[] = '<!DOCTYPE ' . $child->getName();

			// Latest HTML serialization spec omits the public/system ID
			if ( $options['phpCompat'] ?? false ) {
			 if ( $child->getPublicID() !== '' ) {
				$result[] = ' PUBLIC "' . $child->getPublicId() . '"';
			 }

			 if ( $child->getSystemId() !== '' ) {
				$result[] = ' "' . $child->getSystemId() . '"';
			 }
			}

			$result[] = '>';
			if ( $options['phpCompat'] ?? false ) {
				$result[] = "\n";
			}
			break;
		default:
			Util::error( "InvalidStateError" );
		}
	}

	/*
	 * XML NAMES
	 *
	 * In XML, valid names for Elements or Attributes are governed by a
	 * number of overlapping rules, reflecting a gradual standardization
	 * process.
	 *
	 * If terms like 'qualified name,' 'local name', 'namespace', and
	 * 'prefix' are unfamiliar to you, consult:
	 *
	 *      https://www.w3.org/TR/xml/#NT-Name
	 *      https://www.w3.org/TR/xml-names/#NT-QName
	 *
	 * This grammar is from the XML and XML Namespace specs. It specifies whether
	 * a string (such as an element or attribute name) is a valid Name or QName.
	 *
	 * Name           ::= NameStartChar (NameChar)*
	 * NameStartChar  ::= ":" | [A-Z] | "_" | [a-z] |
	 *                    [#xC0-#xD6] | [#xD8-#xF6] | [#xF8-#x2FF] |
	 *                    [#x370-#x37D] | [#x37F-#x1FFF] |
	 *                    [#x200C-#x200D] | [#x2070-#x218F] |
	 *                    [#x2C00-#x2FEF] | [#x3001-#xD7FF] |
	 *                    [#xF900-#xFDCF] | [#xFDF0-#xFFFD] |
	 *                    [#x10000-#xEFFFF]
	 *
	 * NameChar       ::= NameStartChar | "-" | "." | [0-9] |
	 *                    #xB7 | [#x0300-#x036F] | [#x203F-#x2040]
	 *
	 * QName          ::= PrefixedName| UnprefixedName
	 * PrefixedName   ::= Prefix ':' LocalPart
	 * UnprefixedName ::= LocalPart
	 * Prefix         ::= NCName
	 * LocalPart      ::= NCName
	 * NCName         ::= Name - (Char* ':' Char*)
	 *                    # An XML Name, minus the ":"
	 */

	/**
	 * NameStartChar minus :
	 * @see https://www.w3.org/TR/xml/#NT-NameStartChar
	 */
	private const NCNAME_START_CHAR = 'A-Z_a-z\x{C0}-\x{D6}\x{D8}-\x{F6}\x{F8}-\x{2FF}\x{370}-\x{37D}\x{37F}-\x{1FFF}\x{200C}-\x{200D}\x{2070}-\x{218F}\x{2C00}-\x{2FEF}\x{3001}-\x{D7FF}\x{F900}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{EFFFF}';

	/**
	 * NameChar minus :
	 * @see https://www.w3.org/TR/xml/#NT-NameChar
	 */
	private const NCNAME_CHAR = self::NCNAME_START_CHAR . '\x{2D}.0-9\x{B7}\x{0300}-\x{036F}\x{203F}-\x{2040}';

	/**
	 * Name minus :
	 * @see https://www.w3.org/TR/xml-names/#NT-NCName
	 */
	private const NCNAME = '[' . self::NCNAME_START_CHAR . '][' . self::NCNAME_CHAR . ']*';

	/**
	 * QName
	 * @see https://www.w3.org/TR/xml-names/#NT-QName
	 */
	private const QNAME = '/^' . self::NCNAME . '(:' . self::NCNAME . ')?$/Du';

	/**
	 * Fast case QNAME, non-unicode.
	 */
	private const QNAME_ASCII = '/^[A-Za-z_][-A-Za-z_.0-9]*(:[A-Za-z_][-A-Za-z_.0-9]*)?$/D';

	/**
	 * NameStartChar including the :
	 * @see https://www.w3.org/TR/xml/#NT-NameStartChar
	 */
	private const NAME_START_CHAR = self::NCNAME_START_CHAR . ':';

	/**
	 * NameChar including the :
	 * @see https://www.w3.org/TR/xml/#NT-NameChar
	 */
	private const NAME_CHAR = self::NCNAME_CHAR . ':';

	/**
	 * Name
	 * @see https://www.w3.org/TR/REC-xml/#NT-Name
	 */
	private const NAME = '/^[' . self::NAME_START_CHAR . '][' . self::NAME_CHAR . ']*$/Du';

	/**
	 * Fast case NAME, ASCII-only.
	 */
	private const NAME_ASCII = '/^[A-Za-z_:][-A-Za-z_.0-9:]*$/D';

	/**
	 * Char*
	 * @see https://www.w3.org/TR/xml/#NT-Char
	 */
	private const CHARS = '/^[\x{09}\x{0A}\x{0D}\x{20}-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]*$/Du';

	/**
	 * Fast case XML char
	 */
	private const CHARS_ASCII = '/^[\x{09}\x{0A}\x{0D}\x{20}-\x{7F}]*$/D';

	/**
	 * @param string $s
	 * @return bool
	 */
	public static function is_valid_xml_chars( $s ) {
		if ( preg_match( self::CHARS_ASCII, $s ) === 1 ) {
			return true; // Plain ASCII
		}
		if ( preg_match( self::CHARS, $s ) === 1 ) {
			return true; // Unicode BMP
		}
		return false;
	}

	/**
	 * @param string $s
	 * @return bool
	 */
	public static function is_valid_xml_name( $s ) {
		if ( preg_match( self::NAME_ASCII, $s ) === 1 ) {
			return true; // Plain ASCII
		}
		if ( preg_match( self::NAME, $s ) === 1 ) {
			return true; // Unicode BMP
		}
		return false;
	}

	/**
	 * @see https://dom.spec.whatwg.org/#validate
	 * @param string $s
	 * @return bool
	 */
	public static function is_valid_xml_qname( $s ) {
		// Fast case: an ASCII name.
		if ( preg_match( self::QNAME_ASCII, $s ) === 1 ) {
			return true; // Plain ASCII
		}
		// Slower: full unicode pattern.
		if ( preg_match( self::QNAME, $s ) === 1 ) {
			return true;
		}
		return false;
	}

	/**
	 * Validate and extract a namespace and qualifiedName
	 *
	 * Used to map (namespace, qualifiedName) => (namespace, prefix, localName)
	 *
	 * @see https://dom.spec.whatwg.org/#validate-and-extract
	 *
	 * @param ?string &$ns
	 * @param string $qname
	 * @param ?string &$prefix reference (will be NULL or contain prefix string)
	 * @param ?string &$lname reference (will be qname or contain lname string)
	 * @return void
	 * @throws DOMException "NamespaceError"
	 */
	public static function validate_and_extract( ?string &$ns, string $qname, ?string &$prefix, ?string &$lname ): void {
		/*
		 * See https://github.com/whatwg/dom/issues/671
		 * and https://github.com/whatwg/dom/issues/319
		 */
		if ( !self::is_valid_xml_qname( $qname ) ) {
			Util::error( "InvalidCharacterError" );
		}

		if ( $ns === "" ) {
			$ns = null; /* Per spec */
		}

		$pos = strpos( $qname, ':' );
		if ( $pos === false ) {
			$prefix = null;
			$lname = $qname;
		} else {
			$prefix = substr( $qname, 0, $pos );
			$lname  = substr( $qname, $pos + 1 );
		}

		if ( $prefix !== null && $ns === null ) {
			Util::error( "NamespaceError" );
		}
		if ( $prefix === "xml" && $ns !== Util::NAMESPACE_XML ) {
			Util::error( "NamespaceError" );
		}
		if ( ( $prefix === "xmlns" || $qname === "xmlns" ) && $ns !== Util::NAMESPACE_XMLNS ) {
			Util::error( "NamespaceError" );
		}
		if ( $ns === Util::NAMESPACE_XMLNS && !( $prefix === "xmlns" || $qname === "xmlns" ) ) {
			Util::error( "NamespaceError" );
		}
	}
}
