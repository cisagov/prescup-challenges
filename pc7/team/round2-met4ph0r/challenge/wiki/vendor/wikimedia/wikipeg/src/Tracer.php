<?php

namespace Wikimedia\WikiPEG;

interface Tracer {
	public function trace( $event );
}

// Retain the old namespace for backwards compatibility.
class_alias( Tracer::class, 'WikiPEG\Tracer' );
