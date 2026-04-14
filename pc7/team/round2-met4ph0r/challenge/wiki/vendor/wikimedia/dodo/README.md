[![Latest Stable Version]](https://packagist.org/packages/wikimedia/dodo) [![License]](https://packagist.org/packages/wikimedia/dodo)

Dodo
=====================

Dodo is a port of [Domino.js](https://github.com/fgnass/domino) to
PHP, in order to provide a more performant and spec-compliant DOM
library than the DOMDocument PHP classes (`xml` extension), which is
built on [libxml2](www.xmlsoft.org).

Dodo uses a PHP binding for WebIDL defined by
[IDLeDOM](https://packagist.org/packages/wikimedia/idle-dom).
Details of the WebIDL binding can be found in the IDLeDOM documentation.

Additional documentation about the library can be found on
[MediaWiki.org](https://www.mediawiki.org/wiki/Dodo).

Report issues on [Phabricator](https://phabricator.wikimedia.org/maniphest/task/edit/form/1/?projects=Parsoid&title=Dodo:%20).

## Install
This package is [available on Packagist](https://packagist.org/packages/wikimedia/dodo):

```bash
$ composer require wikimedia/dodo
```

## Usage

A better set of examples and tests is coming. For an extremely basic
usage, see [tests/DodoTest.php](tests/DodoTest.php).

## Tests

```bash
$ composer test
```

## Status

This software is near completion, from the perspective of DOM features
used by Parsoid.  Completing the last missing features/fixing the last
remaining bugs to allow Parsoid to run with Dodo as its DOM library is
the prime objective.

After that, performance benchmarking and tuning will be in order.

We run many but not all W3C and WPT tests.  Some of these depend on
JavaScript-specific features and as such will probably always be skipped.
The "known failures" framework we use could use some improvement
in order to provide more granular results.

## Background

(taken from [this page](https://www.mediawiki.org/wiki/Parsoid/PHP/Help_wanted))

> The PHP DOM extension is a wrapper around libxml2 with a thin layer of DOM-compatibility on top ("To some extent libxml2 provides support for the following additional specifications but doesn't claim to implement them completely [...] Document Object Model (DOM) Level 2 Core [...] but it doesn't implement the API itself, gdome2 does this on top of libxml2").

> This is not really remotely close to a modern standards-compliant HTML5 DOM implementation and is barely maintained, much less kept in sync with the WHATWG's pace of change.

The Dodo library implements PHP interfaces generated directly from the
WebIDL sources included in the WHATWG DOM specification by `IDLeDOM`.

## Developer Notes

### Why you need accessors for interface properties

Most DOM implementations have to make a decision about adapting the
specification's notion of an interface property. In many languages,
the only solution is to use accessor functions, e.g. `getFoo()` and
`setFoo(value)` and prevent direct access to the properties themselves.

This is not contrary to the spec's intention, as it is mostly capturing
data representation, and seems to expect some level of indirection between
the library that implements the specification, and the code which calls
that library.

Aside from the usual arguments and reasons for preferring accessors
over direct property access and vice-versa, in this case most implementations
are forced down the accessor route for one reason in particular, and that is
that the current [DOM Specification](https://dom.spec.whatwg.org) defines
certain interface properties as being `readonly`, for example the
[Attr](https://dom.spec.whatwg.org/#interface-attr) interface:

```
interface Attr : Node {
  readonly attribute DOMString? namespaceURI;
  readonly attribute DOMString? prefix;
  readonly attribute DOMString localName;
  readonly attribute DOMString name;
  [CEReactions] attribute DOMString value;

  readonly attribute Element? ownerElement;

  readonly attribute boolean specified; // useless; always returns true
};
```

This essentially means that once their value has been set once (in the
constructor), it cannot be modified, but can still be accessed.

PHP currently lacks a way to implement readonly properties without
incurring significant performance penalties. Although there have been
several RFCs ([readonly properties](https://wiki.php.net/rfc/readonly_properties)
and [property accessors syntax](https://wiki.php.net/rfc/propertygetsetsyntax-v1.2)),
they have always been declined.

So, in the PHP binding for WebIDL which Dodo uses, we have explicit
accessors for each WebIDL property.
If a class property "foo" is not marked `readonly`, then there
will be methods `getFoo()` and `setFoo($value)` defined on the class.
If "foo" is marked `readonly`, then only `getFoo()` will be defined on the
class.

We bridge the gap between the spec and common usage by defining special
"magic methods" (`__get`, `__set`, etc) in order to support the common
`$obj->foo` style of access.  These will be less-performant than
accessing the appropriate `getFoo` or `setFoo` method directly, and
so for performance Dodo internally avoids using this style of access.

However, if you're reading this, and PHP has passed an RFC with
improved JavaScript-style property accessor functions,
you know what to do: replace the `__get` and `__set` magic methods
with appropriate property accessors.  (This can probably be done
in IDLeDOM's generated `Helper` classes, and may not actually need
any code change in Dodo itself.)

### Strings specified as "NULL or non-empty"

It isn't uncommon for interface properties to have type written
`DOMString?`, which is not a single type, but rather indicates
that the field may take either of type `NULL`, or type `DOMString`
(they are distinct types).

For example, the `namespaceURI` property from the [Attr](https://dom.spec.whatwg.org/#interface-attr) interface:

```
interface Attr : Node {
  readonly attribute DOMString? namespaceURI;
  /* ... */
};
```

However, it's common for there to be an additional constraint on the value of
such properties, one which is not visible from inspection of the interface
definition in IDL.

For example, [namespaceURI](https://dom.spec.whatwg.org/#dom-attr-namespaceuri)
is defined to return the
[namespace](https://dom.spec.whatwg.org/#concept-attribute-namespace), which is
either "NULL or a non-empty string".

Well, this is a bit annoying because it's certainly possible to provide the
empty string to any interface which accepts arguments of type `DOMString`.

Because of this common stipulation, you would find in the code something
that looks like:
```
class Attr extends Node
{
        protected $namespaceURI = NULL;

        public function construct(string? $namespace=NULL /* ... other arguments ... */)
        {
                if ($namespace !== '') {
                        $this->$namespaceURI = $namespace;
                }

                /* ... */
        }

        /* ... */
}
```
The caller can provide either a string or NULL, but the assignment
will only occur if it is NOT the empty string. In that case,
`$this->$namespaceURI` will retain its default value of `NULL`.

### Strings specified as "non-empty"

This seems simpler, but it's actually worse than "NULL or non-empty"!

Properties that must be "non-empty strings", such as
[localName](https://dom.spec.whatwg.org/#concept-attribute-local-name),
are usually integral to the object functioning properly. `localName`, for
example, is the name of the attribute.

Unfortunately, an empty string is also a string, and even a `DOMString`. So
providing the empty string is valid when the function's argument type
is `DOMString` (or `string`, in PHP's type hinting). But in the case of
constructors, once we find out that this argument is the empty string,
the entire object is undefined.

But in PHP, it's not possible to "abort" the constructor -- an object of the
specified class will always be returned to the caller.
In old versions of PHP, you could actually do something like `unset($this)`
inside the constructor. Pretty cool, but you haven't been able to do it for
years. What a pain...

So we probably have to throw an Exception, or make a "non-empty string" class.

### Readonly does not mean immutable

Read-only/read-write and mutable/immutable

These are not equivalent, though it seems at first they might be.

        Immutable <=> read-only
        Read-write => mutable

But

        mutable =/> read-write

For example, on an Attr object, ownerElement is a read-only property,
but it can still change if we associate the Attr node with another
element.

For another example, the name property of an attribute is read-only,
but the prefix property is read-write, and since I can mutate the prefix
property, I can mutate the name (which includes this prefix), thus
making the name property mutable, even if it's read-only.

Basically, there are properties where even if you can't update them
directly, you can update something that is used to compute their value.

### Methods that are somewhere between abstract and concrete...

The `Node` interface methods `isEqualNode` and `cloneNode` are two good
examples of things that are annoying. Both of them first do something
that is common among all `Node` objects, and then proceed to do something
that is unique to whatever class has extended `Node`, for example `Attr`.

That means that if you want to implement them as `abstract`, you have
to include this boilerplate `Node`-common stuff in all of the subclass
implementations of the abstract method. What a pain.

So instead, we have abstract methods like `_subclass_isEqualNode`, which
are called by `Node::isEqualNode` when it's time to do the subclass-specific
part.

### Other readability conventions

- If a property accessor or method is part of the spec, it is written
exactly as in the spec IDL (naturally).
- If a property or method is for internal-use, it is prefixed with '_'.

### Potential bugs in Domino.js

It appears that HTMLCollection will not recompute the cache
when an Element's `id` or `name` attribute changes. However,
these are used to index two internal caches, and so the HTMLCollection
will no longer be "live".

Solution would be to update `lastModTime` when those attributes are
mutated.

### Performance tips

- Make sure your Element ids stay unique. The spec requires that you
  return the first Element with that id, in document order, and it is
  not very performant to compute the document order.

## License and Credits

The initial version of this code was written by Jason Linehan.
Further improvements were made by C. Scott Ananian (IDLeDOM, bug fixes,
missing features) and Tim Abdullin (test suite).

This code is (c) Copyright 2019-2021 Wikimedia Foundation.
It is distributed under the MIT license; see LICENSE for more
info.

---
[Latest Stable Version]: https://poser.pugx.org/wikimedia/dodo/v/stable.svg
[License]: https://poser.pugx.org/wikimedia/dodo/license.svg
