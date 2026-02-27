<?php

declare( strict_types = 1 );

namespace Wikimedia\Dodo\Internal;

use Exception;

/**
 * Helper trait that uses Dodo's UnimplementedException to fill out
 * the ::_unimplemented() abstract method from IDLeDOM's stubs.
 */
trait UnimplementedTrait {

	// Underscore is used to avoid conflicts with DOM-reserved names
	// phpcs:disable PSR2.Methods.MethodDeclaration.Underscore
	// phpcs:disable MediaWiki.NamingConventions.LowerCamelFunctionsName.FunctionName

	protected function _unimplemented(): Exception {
		// Identify the function which is unimplemented from the backtrace
		$dbt = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 2 );
		$class = $dbt[1]['class'] ?? '<unknown class>';
		$func = $dbt[1]['function'] ?? '<unknown function>';
		return new UnimplementedException( "$class::$func" );
	}

	// phpcs:enable
}
