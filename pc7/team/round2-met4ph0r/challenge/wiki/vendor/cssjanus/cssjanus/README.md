[![Build Status](https://travis-ci.com/cssjanus/php-cssjanus.svg?branch=main)](https://travis-ci.com/cssjanus/php-cssjanus) [![Packagist](https://img.shields.io/packagist/v/cssjanus/cssjanus.svg?style=flat)](https://packagist.org/packages/cssjanus/cssjanus) [![Coverage Status](https://coveralls.io/repos/github/cssjanus/php-cssjanus/badge.svg?branch=main)](https://coveralls.io/github/cssjanus/php-cssjanus?branch=main)

# CSSJanus

Convert CSS stylesheets between left-to-right and right-to-left.

## Usage

```php
transform( string $css, bool $swapLtrInURL = false, bool $swapLeftInURL = false ) : string
```

Parameters;

* ``$css`` (string) Stylesheet to transform.
* ``$swapLtrInURL`` (boolean) Swap `ltr` to `rtl` direction in URLs.
* ``$swapLeftInURL`` (boolean) Swap `left` and `right` edges in URLs.

Example:

```php
$rtlCss = CSSJanus::transform( $ltrCss );
```

### Preventing flipping

If a rule is not meant to be flipped by CSSJanus, use a `/* @noflip */` comment to protect the rule.

```css
.rule1 {
  /* Will be converted to margin-right */
  margin-left: 1em;
}
/* @noflip */
.rule2 {
  /* Will be preserved as margin-left */
  margin-left: 1em;
}
```

## Who uses CSSJanus?

* **[Wikimedia Foundation](https://www.wikimedia.org/)**, the non-profit behind Wikipedia and other free knowledge projects.<br/>Used in [MediaWiki](https://www.mediawiki.org/wiki/MediaWiki), on [Wikipedia](https://ar.wikipedia.org/), and [other projects](https://doc.wikimedia.org/).

## Port

This is a PHP port of the Node.js implementation of CSSJanus, and was originally
based on a [Google project](http://code.google.com/p/cssjanus/).

Feature requests and bugs related to the actual CSS transformation logic or test
cases of it, should be submitted upstream at <https://github.com/cssjanus/cssjanus>.

Upstream releases will be ported here.
