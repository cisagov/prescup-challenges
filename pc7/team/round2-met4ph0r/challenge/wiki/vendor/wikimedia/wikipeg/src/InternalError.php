<?php

namespace Wikimedia\WikiPEG;

class InternalError extends \Exception {
}

// Retain the old namespace for backwards compatibility.
class_alias( InternalError::class, 'WikiPEG\InternalError' );
