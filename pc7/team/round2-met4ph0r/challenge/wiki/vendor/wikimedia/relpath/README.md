RelPath
=======

RelPath is a small PHP library for computing a relative filepath to some path,
either from the current directory or from an optional start directory.

Here is how you use it:

```php
$relPath = \Wikimedia\RelPath::getRelativePath( '/srv/mediawiki/resources/src/startup.js', '/srv/mediawiki' );
// Result: "resources/src/startup.js"

$fullPath = \Wikimedia\RelPath::joinPath( '/srv/mediawiki', 'resources/src/startup.js' );
// Result: "/srv/mediawiki/resources/src/startup.js"

$fullPath = \Wikimedia\RelPath::joinPath( '/srv/mediawiki', '/var/startup/startup.js' );
// Result: "/var/startup/startup.js"
```

The `RelPath::joinPath()` function provided here is analogous to `os.path.join()` in Python,
and `path.join()` found in Node.js.

License
-------

MIT
