# Release History

## 4.0.0
* Fix multiple phpcs codesniffer warnings (Zabe)

-
* build: Updating composer dependencies (libraryupgrader)
* build: Cleanup and improve .phpcs.xml (Umherirrender)
* build: Updating mediawiki/mediawiki-codesniffer to 37.0.0 (libraryupgrader)
* build: Updating composer dependencies (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 38.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-phan-config to 0.11.1 (libraryupgrader)
* tests: Add IPv4 test cases for IPUtils::splitHostAndPort() (Reedy)

## 3.0.2
* Remove redundant strpos/substr code from canonicalize() (Reedy)
* Allow wikimedia/ip-set ^3.0.0 (Reedy)

-
* tests: Add test case to make IPUtils::parseRange6 100% covered (Reedy)
* build: Updating composer dependencies (libraryupgrader)

## v3.0.1
* Revert "Stop allowing invalid /0 subnet" (Reedy)
* Update return type for IPUtils::parseCIDR6 (Reedy)
* Allow spaces around hyphenated IP ranges (Reedy)

—
* tests: Add @codeCoverageIgnore for 32-bit and Windows only code (Reedy)
* tests: Exercise IPUtils::parseCIDR6() where count( $parts ) != 2 (Reedy)
* tests: Increase test coverage of IPUtils::canonicalize() (Reedy)
* HISTORY: Add entries for changes since v3.0.0 (James D. Forrester)
* HISTORY: Split 'features' and 'code fixes' sections (James D. Forrester)
* build: Updating mediawiki/mediawiki-codesniffer to 34.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-phan-config to 0.10.6 (libraryupgrader)
* build: Updating ockcyp/covers-validator to 1.3.1 (libraryupgrader)
* Simplify code paths in IPUtils::parseRange6 (Reedy)

## v3.0.0
* Add method to retrieve all IPs in a given range (Ammar Abdulhamid)
* Cast isValidIPv[46] return value to bool (Reedy)

—
* Code cleanup: Remove unneeded parenthesis (Umherirrender)
* Fix up some issues with 2.0.0 canonicalize() (Reedy)
* tests: Add a couple more @covers (Reedy)
* tests: Add case for IPUtils::parseCIDR() being given IPv6 (Reedy)
* tests: Add some more test cases to add some more coverage (Reedy)
* tests: Add test for another edge case of IPUtils::parseRange() (Reedy)
* tests: Add tests for IPUtils::parseRange() for single IPs (Reedy)
* tests: Improve test coverage (Ammar Abdulhamid)
* tests: Mark IPUtilsTest::testToHex() as covering IPUtils:IPv6ToRawHex() (Reedy)
* README: Fix markdown display of code (DannyS712)
* build: Drop phan-taint-check-plugin, now in mediawiki-phan-config (James D. Forrester)
* build: Updating composer dependencies (libraryupgrader)
* build: Updating composer dependencies (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 30.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 31.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 33.0.0 (libraryupgrader)
* build: Upgrade mediawiki-phan-config from 0.9.2 to 0.10.2 (James D. Forrester)

## v2.0.0
* Add isValidIPv4 and isValidIPv6 (Reedy)
* Allow explicit ranges in IPUtils::isValidRange() (Reedy)
* Check for IPv4 before IPv6 in IPUtils::isValidRange (Reedy)
* Combine hexToOctet and hexToQuad tests to cover formatHex (Reedy)
* Drop PHP 7.0/7.1 and HHVM support (James D. Forrester)
* Fix return values where function doesn't always return [string, string] (Reedy)
* Make getSubnet actually not accept invalid IPv4 addresses (Reedy)
* Remove unnecessary temporary variables (Reedy)
* Stop allowing invalid /0 subnet (Reedy)

—
* tests: Add IPv4 tests for IPUtils::getSubnet() (Reedy)
* tests: Add IPv6 coverage of sanitizeIP() (Jforrester)
* tests: Add test for IPUtils::canonicalize() for IPv6 loopback (Reedy)
* tests: Add tests to cover IPUtils::parseRange (Reedy)
* tests: Fix provider for comments (Reedy)
* tests: Make tests for IPUtils::isInRanges() test IPUtils::isInRanges() (Reedy)
* build: Add phan and fix issues (Reedy)
* build: Drop Travis testing, no extra advantage over Wikimedia CI and runs post-merge anyway (James D. Forrester)
* build: Follow-up 8270f11003: Also drop .travis.yml reference from .gitattributes (James D. Forrester)
* build: Normalise comments to // rather than # (Reedy)
* build: Require PHPUnit 8 like MW core (Daimona Eaytoy)
* build: Updating composer dependencies (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 26.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 28.0.0 (libraryupgrader)
* build: Updating mediawiki/mediawiki-codesniffer to 29.0.0 (libraryupgrader)
* build: Updating mediawiki/minus-x to 0.3.2 (libraryupgrader)

## v1.0.0
* Initial import from MediaWiki core (Kunal Mehta)

—
* Remove @since tags (Kunal Mehta)
* Turn global RE_ constants into class constants and document visibility (Kunal Mehta)
* README: Fix example to use right class name (Kunal Mehta)
* README: Fix link (Kunal Mehta)
* Add HISTORY (Kunal Mehta)
