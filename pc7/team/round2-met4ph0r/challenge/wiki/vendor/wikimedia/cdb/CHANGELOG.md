# Changelog

## 2.0.0

The library now requires PHP 7.2 or later.

*  Drop PHP 5.5/5.6/7.0/7.1 and HHVM support (James D. Forrester)
*  Cli: Add new `cdb` CLI (Timo Tijhof)

## 1.4.1

* Reader\Hash: Avoid use of wikimedia/assert (Ori Livneh)

## 1.4.0

*  Add Reader\Hash, a new faux CDB interface wrapping an in-memory array (Daniel Kinzler)
*  Reader\PHP: Avoid reading past the last key in `nextkey()` (Ori Livneh)
*  Reader\PHP: Optimize `readInt32` implementation (Ori Livneh)
*  Reader\PHP: Improve performance (Ori Livneh)

## 1.1.0

*  Reader\PHP: Simplify `nextkey` by using `unpack31`, and reuse method for `firstkey` (Thomas Colomb)
*  Use PHP_OS rather than php_uname, which may be disabled (Chad Horohoe)

## 1.0.0

Initial release.
