<?php

namespace Shellbox\Command;

use Shellbox\Shellbox;

/**
 * A ulimit/cgroup wrapper implemented as a bash script
 */
class BashWrapper extends Wrapper {
	/** @var bool|string */
	private $cgroup;

	/**
	 * @param string|false $cgroup Under Linux: a cgroup directory used to constrain
	 *   memory usage of shell commands. The directory must be writable by the
	 *   web server. If this is false, no memory limit will be applied.
	 */
	public function __construct( $cgroup = false ) {
		parent::__construct();
		if ( strval( $cgroup ) === '' ) {
			$cgroup = '';
		}
		$this->cgroup = $cgroup;
	}

	public function wrap( Command $command ) {
		$time = intval( $command->getCpuTimeLimit() );
		$wallTime = intval( $command->getWallTimeLimit() );
		$mem = intval( $command->getMemoryLimit() );
		$filesize = intval( $command->getFileSizeLimit() );

		if ( $time > 0 || $mem > 0 || $filesize > 0 || $wallTime > 0 ) {
			$cmd = '/bin/bash ' . Shellbox::escape( __DIR__ . '/limit.sh' ) . ' ' .
				Shellbox::escape( $command->getCommandString() ) . ' ' .
				Shellbox::escape(
					"SB_INCLUDE_STDERR=" . ( $command->getIncludeStderr() ? '1' : '' ) . ';' .
					"SB_CPU_LIMIT=$time; " .
					'SB_CGROUP=' . Shellbox::escape( $this->cgroup ) . '; ' .
					"SB_MEM_LIMIT=$mem; " .
					"SB_FILE_SIZE_LIMIT=$filesize; " .
					"SB_WALL_CLOCK_LIMIT=$wallTime; " .
					"SB_USE_LOG_PIPE=yes"
				);
			$command->unsafeCommand( $cmd )
				->useLogPipe();
			if ( $command->getAllowedPaths() ) {
				// If specific paths have been allowed, make sure we explicitly
				// allow limit.sh. We don't do this unconditionally because it
				// doesn't work as expected in firejail, see T274474, T182486
				$command->allowPath( __DIR__ . '/limit.sh' );
			}
		}
	}

	/**
	 * If a cgroup is used, it is a system-level container. Otherwise it is
	 * just setrlimit() and can run inside firejail etc. (T274942)
	 *
	 * @return int
	 */
	public function getPriority() {
		if ( strlen( $this->cgroup ) ) {
			return 60;
		} else {
			return 20;
		}
	}
}
