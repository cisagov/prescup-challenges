<?php

declare( strict_types = 1 );
// phpcs:disable Generic.Files.LineLength.TooLong

namespace Wikimedia\Dodo;

/******************************************************************************
 * DOMException.php
 * ----------------
 * (Mostly) implements the WebIDL-1 DOMException interface
 * https://www.w3.org/TR/WebIDL-1/#idl-DOMException*
 * @phan-forbid-undeclared-magic-properties
 */
class DOMException extends \Exception implements \Wikimedia\IDLeDOM\DOMException {

	// Helper functions from IDLeDOM
	use \Wikimedia\IDLeDOM\Helper\DOMException;

	private const ERR_CODE_DOES_NOT_EXIST = 0;	/* [Dodo] Errors without Legacy code */

	private const ERROR_NAME_TO_CODE = [
		'IndexSizeError' => self::INDEX_SIZE_ERR,
		'HierarchyRequestError' => self::HIERARCHY_REQUEST_ERR,
		'WrongDocumentError' => self::WRONG_DOCUMENT_ERR,
		'InvalidCharacterError' => self::INVALID_CHARACTER_ERR,
		'NoModificationAllowedError' => self::NO_MODIFICATION_ALLOWED_ERR,
		'NotFoundError' => self::NOT_FOUND_ERR,
		'NotSupportedError' => self::NOT_SUPPORTED_ERR,
		'InUseAttributeError' => self::INUSE_ATTRIBUTE_ERR,
		'InvalidStateError' => self::INVALID_STATE_ERR,
		'SyntaxError' => self::SYNTAX_ERR,
		'InvalidModificationError' => self::INVALID_MODIFICATION_ERR,
		'NamespaceError' => self::NAMESPACE_ERR,
		'InvalidAccessError' => self::INVALID_ACCESS_ERR,
		'SecurityError' => self::SECURITY_ERR,
		'NetworkError' => self::NETWORK_ERR,
		'AbortError' => self::ABORT_ERR,
		'URLMismatchError' => self::URL_MISMATCH_ERR,
		'QuotaExceededError' => self::QUOTA_EXCEEDED_ERR,
		'TimeoutError' => self::TIMEOUT_ERR,
		'InvalidNodeTypeError' => self::INVALID_NODE_TYPE_ERR,
		'DataCloneError' => self::DATA_CLONE_ERR,
		'EncodingError' => self::ERR_CODE_DOES_NOT_EXIST,
		'NotReadableError' => self::ERR_CODE_DOES_NOT_EXIST,
		'UnknownError' => self::ERR_CODE_DOES_NOT_EXIST,
		'ConstraintError' => self::ERR_CODE_DOES_NOT_EXIST,
		'DataError' => self::ERR_CODE_DOES_NOT_EXIST,
		'TransactionInactiveError' => self::ERR_CODE_DOES_NOT_EXIST,
		'ReadOnlyError' => self::ERR_CODE_DOES_NOT_EXIST,
		'VersionError' => self::ERR_CODE_DOES_NOT_EXIST,
		'OperationError' => self::ERR_CODE_DOES_NOT_EXIST
	];

	private const ERROR_NAME_TO_MESSAGE = [
		'IndexSizeError' => 'INDEX_SIZE_ERR (1): the index is not in the allowed range',
		'HierarchyRequestError' => 'HIERARCHY_REQUEST_ERR (3): the operation would yield an incorrect nodes model',
		'WrongDocumentError' => 'WRONG_DOCUMENT_ERR (4): the object is in the wrong Document, a call to importNode is required',
		'InvalidCharacterError' => 'INVALID_CHARACTER_ERR (5): the string contains invalid characters',
		'NoModificationAllowedError' => 'NO_MODIFICATION_ALLOWED_ERR (7): the object can not be modified',
		'NotFoundError' => 'NOT_FOUND_ERR (8): the object can not be found here',
		'NotSupportedError' => 'NOT_SUPPORTED_ERR (9): this operation is not supported',
		'InUseAttributeError' => 'INUSE_ATTRIBUTE_ERR (10): setAttributeNode called on owned Attribute',
		'InvalidStateError' => 'INVALID_STATE_ERR (11): the object is in an invalid state',
		'SyntaxError' => 'SYNTAX_ERR (12): the string did not match the expected pattern',
		'InvalidModificationError' => 'INVALID_MODIFICATION_ERR (13): the object can not be modified in this way',
		'NamespaceError' => 'NAMESPACE_ERR (14): the operation is not allowed by Namespaces in XML',
		'InvalidAccessError' => 'INVALID_ACCESS_ERR (15): the object does not support the operation or argument',
		'SecurityError' => 'SECURITY_ERR (18): the operation is insecure',
		'NetworkError' => 'NETWORK_ERR (19): a network error occurred',
		'AbortError' => 'ABORT_ERR (20): the user aborted an operation',
		'URLMismatchError' => 'URL_MISMATCH_ERR (21): the given URL does not match another URL',
		'QuotaExceededError' => 'QUOTA_EXCEEDED_ERR (22): the quota has been exceeded',
		'TimeoutError' => 'TIMEOUT_ERR (23): a timeout occurred',
		'InvalidNodeTypeError' => 'INVALID_NODE_TYPE_ERR (24): the supplied node is invalid or has an invalid ancestor for this operation',
		'DataCloneError' => 'DATA_CLONE_ERR (25): the object can not be cloned.',
		'EncodingError' => 'The encoding operation (either encoding or decoding) failed.',
		'NotReadableError' => 'The I/O read operation failed.',
		'UnknownError' => 'The operation failed for an unknown transient reason (e.g. out of memory)',
		'ConstraintError' => 'A mutation operation in a transaction failed because a constraint was not satisfied.',
		'DataError' => 'Provided data is inadequate',
		'TransactionInactiveError' => 'A request was placed against a transaction which is currently not active, or which is finished.',
		'ReadOnlyError' => 'The mutating operation was attempted in a readonly transaction.',
		'VersionError' => 'An attempt was made to open a database using a lower version than the existing version.',
		'OperationError' => 'The operation failed for an operation-specific reason.'
	];

	/**
	 * The name of the DOMException.
	 * @var string
	 */
	private $_name;

	/**
	 * [WEB-IDL-1] This is the actual constructor prototype.
	 * I think the invocation is ridiculous, so we wrap it
	 * in an error() function (see Util.php).
	 * @param ?string $message
	 * @param ?string $name
	 */
	public function __construct( ?string $message = null, ?string $name = null ) {
		$this->_name = $name ?? "Error";
		$err_msg  = self::ERROR_NAME_TO_MESSAGE[$this->_name] ?? "";
		$err_code = self::ERROR_NAME_TO_CODE[$this->_name] ?? self::ERR_CODE_DOES_NOT_EXIST;

		parent::__construct( $message ?? $err_msg, $err_code );
	}

	/** @inheritDoc */
	public function getName(): string {
		return $this->_name;
	}

	/**
	 * Human-readable represetation of this exception.
	 * @return string
	 */
	public function __toString(): string {
		return __CLASS__ . ': [' . $this->_name . '] ' . $this->getMessage();
	}
}
