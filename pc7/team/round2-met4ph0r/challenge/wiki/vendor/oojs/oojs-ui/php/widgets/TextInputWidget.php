<?php

namespace OOUI;

/**
 * Input widget with a text field.
 */
class TextInputWidget extends InputWidget {
	use IconElement;
	use IndicatorElement;
	use FlaggedElement;
	use RequiredElement;

	/* Properties */

	/**
	 * Input field type.
	 *
	 * @var string
	 */
	protected $type = null;

	/**
	 * Prevent changes.
	 *
	 * @var bool
	 */
	protected $readOnly = false;

	/**
	 * @param array $config Configuration options
	 *      - string $config['type'] HTML tag `type` attribute: 'text', 'password', 'email',
	 *          'url' or 'number'. (default: 'text')
	 *      - string $config['placeholder'] Placeholder text
	 *      - bool $config['autofocus'] Ask the browser to focus this widget, using the 'autofocus'
	 *          HTML attribute (default: false)
	 *      - bool $config['readOnly'] Prevent changes (default: false)
	 *      - int $config['maxLength'] Maximum allowed number of characters to input
	 *          For unfortunate historical reasons, this counts the number of UTF-16 code units rather
	 *          than Unicode codepoints, which means that codepoints outside the Basic Multilingual
	 *          Plane (e.g. many emojis) count as 2 characters each.
	 *      - bool|string $config['autocomplete'] If the field should support autocomplete
	 *          or not (default: true). Can also be an autocomplete type hint.
	 *      - bool $config['spellcheck'] If the field should support spellcheck
	 *          or not (default: browser-dependent)
	 */
	public function __construct( array $config = [] ) {
		// Config initialization
		$config = array_merge( [
			'type' => 'text',
			'readOnly' => false,
			'autofocus' => false,
		], $config );
		if ( is_bool( $config['autocomplete'] ?? null ) ) {
			$config['autocomplete'] = $config['autocomplete'] ? 'on' : 'off';
		}

		// Parent constructor
		parent::__construct( $config );

		// Properties
		$this->type = $this->getSaneType( $config );

		// Traits
		$this->initializeIconElement( $config );
		$this->initializeIndicatorElement( $config );
		$this->initializeFlaggedElement(
			array_merge( [ 'flagged' => $this ], $config )
		);
		$this->initializeRequiredElement( $config );

		// Initialization
		$this
			->addClasses( [
				'oo-ui-textInputWidget',
				'oo-ui-textInputWidget-type-' . $this->type,
				'oo-ui-textInputWidget-php',
			] )
			->appendContent( $this->icon, $this->indicator );
		$this->setReadOnly( $config['readOnly'] );
		if ( isset( $config['placeholder'] ) ) {
			$this->input->setAttributes( [ 'placeholder' => $config['placeholder'] ] );
		}
		if ( isset( $config['maxLength'] ) ) {
			$this->input->setAttributes( [ 'maxlength' => $config['maxLength'] ] );
		}
		if ( $config['autofocus'] ) {
			$this->input->setAttributes( [ 'autofocus' => 'autofocus' ] );
		}
		if ( isset( $config['autocomplete'] ) ) {
			$this->input->setAttributes( [ 'autocomplete' => $config['autocomplete'] ] );
		}
		if ( isset( $config['spellcheck'] ) ) {
			$this->input->setAttributes( [ 'spellcheck' => $config['spellcheck'] ? 'true' : 'false' ] );
		}
	}

	/**
	 * Check if the widget is read-only.
	 *
	 * @return bool
	 */
	public function isReadOnly() {
		return $this->readOnly;
	}

	/**
	 * Set the read-only state of the widget. This should probably change the widget's appearance and
	 * prevent it from being used.
	 *
	 * @param bool $state Make input read-only
	 * @return $this
	 */
	public function setReadOnly( $state ) {
		$this->readOnly = (bool)$state;
		if ( $this->readOnly ) {
			$this->input->setAttributes( [ 'readonly' => 'readonly' ] );
		} else {
			$this->input->removeAttributes( [ 'readonly' ] );
		}
		return $this;
	}

	protected function getInputElement( $config ) {
		if ( $this->getSaneType( $config ) === 'number' ) {
			return ( new Tag( 'input' ) )->setAttributes( [
				'step' => 'any',
				'type' => 'number',
			] );
		} else {
			return ( new Tag( 'input' ) )->setAttributes( [ 'type' => $this->getSaneType( $config ) ] );
		}
	}

	protected function getSaneType( $config ) {
		$allowedTypes = [
			'text',
			'password',
			'email',
			'url',
			'number'
		];
		return in_array( $config['type'], $allowedTypes ) ? $config['type'] : 'text';
	}

	public function getConfig( &$config ) {
		if ( $this->type !== 'text' ) {
			$config['type'] = $this->type;
		}
		if ( $this->isReadOnly() ) {
			$config['readOnly'] = true;
		}
		$placeholder = $this->input->getAttribute( 'placeholder' );
		if ( $placeholder !== null ) {
			$config['placeholder'] = $placeholder;
		}
		$maxlength = $this->input->getAttribute( 'maxlength' );
		if ( $maxlength !== null ) {
			$config['maxLength'] = $maxlength;
		}
		$autofocus = $this->input->getAttribute( 'autofocus' );
		if ( $autofocus !== null ) {
			$config['autofocus'] = true;
		}
		$autocomplete = $this->input->getAttribute( 'autocomplete' );
		if ( $autocomplete !== null ) {
			$config['autocomplete'] = $autocomplete;
		}
		return parent::getConfig( $config );
	}
}
