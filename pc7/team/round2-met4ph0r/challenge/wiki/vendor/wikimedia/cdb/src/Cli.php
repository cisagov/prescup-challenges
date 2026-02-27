<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

namespace Cdb;

/**
 * @internal For use by bin/cdb only.
 */
final class Cli {
	/** @var int $exitCode */
	private $exitCode = 0;

	/** @var resource $out */
	private $out;

	/** @var string $self */
	private $self;

	/** @var string $filepath */
	private $filepath;

	/** @var string $action */
	private $action;

	/** @var string[] $params */
	private $params;

	/**
	 * @param resource $out An open output handle for fwrite()
	 * @param string[] $argv
	 */
	public function __construct( $out, array $argv ) {
		$this->out = $out;
		$this->self = $argv[0] ?? './bin/cdb';
		$this->filepath = $argv[1] ?? '';
		$this->action = $argv[2] ?? '';
		$this->params = array_slice( $argv, 3 );
	}

	/** Main method. */
	public function run() {
		try {
			switch ( $this->action ) {
			case 'get':
				$this->runGet();
				break;
			case 'list':
				$this->runList();
				break;
			case 'match':
				$this->runMatch();
				break;
			default:
				$this->exitCode = 1;
				$this->help();
				break;
			}
		} catch ( \Throwable $e ) {
			$this->exitCode = 1;
			$this->output( $e );
		}
	}

	private function runGet(): void {
		if ( count( $this->params ) !== 1 ) {
			$this->error( "The 'get' action requires one parameter." );
			return;
		}
		$key = $this->params[0];

		$dbr = Reader::open( $this->filepath );
		$value = $dbr->get( $key );
		if ( $value == false ) {
			$this->error( "Key '$key' not found." );
			return;
		}
		$this->output( $value );
	}

	private function runList(): void {
		if ( count( $this->params ) > 1 ) {
			$this->error( "The 'list' action accepts only one parameter." );
			return;
		}
		$max = (int)( $this->params[0] ?? '100' );

		$dbr = Reader::open( $this->filepath );
		$key = $dbr->firstkey();
		$count = 0;
		while ( $key !== false && $count < $max ) {
			$this->output( $key );
			$count++;
			$key = $dbr->nextkey();
		}
		if ( $count === $max && $key !== false ) {
			$this->output( "\n(more keys exist…)" );
		}
	}

	private function runMatch(): void {
		if ( count( $this->params ) !== 1 ) {
			$this->error( "The 'match' action requires one parameter." );
			return;
		}
		$pattern = $this->params[0];
		if ( preg_match( $pattern, '' ) === false ) {
			$this->error( 'Invalid regular expression pattern.' );
			return;
		}

		$dbr = Reader::open( $this->filepath );
		$key = $dbr->firstkey();
		while ( $key !== false ) {
			if ( preg_match( $pattern, $key ) ) {
				$this->output( $key );
			}
			$key = $dbr->nextkey();
		}
	}

	private function help(): void {
		$this->output( <<<TEXT
usage: {$this->self} <file> [<action>=list] [<parameters...>]

actions:
   get <key>         Get the value for a given key.
   list [<max>=100]  List all keys in the file
   match <pattern>   List keys matching a regular expression.
                     The pattern must include delimiters (e.g. / or #).
TEXT
		);
	}

	private function error( string $text ): void {
		$this->exitCode = 1;
		$this->output( "\nerror: $text\n------\n" );
		$this->help();
	}

	private function output( string $text ): void {
		fwrite( $this->out, $text . "\n" );
	}

	/**
	 * Get exit status code for the process.
	 *
	 * @return int
	 */
	public function getExitCode(): int {
		return $this->exitCode;
	}
}
