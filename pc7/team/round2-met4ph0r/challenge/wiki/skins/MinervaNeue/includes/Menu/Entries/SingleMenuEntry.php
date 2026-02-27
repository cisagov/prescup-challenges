<?php
/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

namespace MediaWiki\Minerva\Menu\Entries;

use MediaWiki\Minerva\MinervaUI;
use Message;

/**
 * Model for a simple menu entries with label and icon
 */
class SingleMenuEntry implements IMenuEntry {
	/**
	 * @var string
	 */
	private $name;
	/**
	 * @var array
	 */
	private $attributes;
	/**
	 * @var bool
	 */
	private $isJSOnly;

	/**
	 * Create a simple menu element with one component
	 *
	 * @param string $name An unique menu element identifier
	 * @param string $text Text to show on menu element
	 * @param string $url URL menu element points to
	 * @param string|array $className Additional CSS class names.
	 */
	public function __construct( $name, $text, $url, $className = '' ) {
		$this->name = $name;
		$menuClass = 'menu__item--' . $name;

		$this->attributes = [
			'icon' => null,
			'text' => $text,
			'href' => $url,
			'class' => is_array( $className ) ?
				implode( ' ', $className + [ $menuClass ] ) :
					ltrim( $className . ' ' . $menuClass ),
		];
	}

	/**
	 * Override the icon used in the home menu entry.
	 *
	 * @param string $icon
	 * @return $this
	 */
	public function overrideIcon( $icon ) {
		$this->setIcon( str_replace( 'minerva-', '', $icon ) );
		return $this;
	}

	/**
	 * Override the text used in the home menu entry.
	 *
	 * @param string $text
	 * @return $this
	 */
	public function overrideText( $text ) {
		$this->attributes['text'] = $text;
		return $this;
	}

	/**
	 * Create a Single Menu entry with text, icon and active click tracking
	 *
	 * @param string $name Entry identifier
	 * @param string $text Entry label
	 * @param string $url The URL entry points to
	 * @param string $className Optional HTML classes
	 * @param string|null $icon defaults to $name if not specified
	 * @param bool $trackable Whether an entry will track clicks or not. Default is false.
	 * @return static
	 */
	public static function create( $name, $text, $url, $className = '', $icon = null, $trackable = false ) {
		$entry = new static( $name, $text, $url, $className );
		if ( $trackable ) {
			$entry->trackClicks( $name );
		}
		if ( $icon === null ) {
			$icon = $name;
		}
		$entry->setIcon( $icon );
		return $entry;
	}

	/**
	 * @inheritDoc
	 */
	public function getName() {
		return $this->name;
	}

	/**
	 * @inheritDoc
	 */
	public function getCSSClasses(): array {
		return $this->isJSOnly ? [ 'jsonly' ] : [];
	}

	/**
	 * @inheritDoc
	 */
	public function getComponents(): array {
		return [ $this->attributes ];
	}

	/**
	 * @param string $eventName Should clicks be tracked. To override the tracking code
	 * pass the tracking code as string
	 * @return $this
	 */
	public function trackClicks( $eventName ) {
		$this->attributes['data-event-name'] = 'menu.' . $eventName;
		return $this;
	}

	/**
	 * Set the Menu entry icon
	 * @param string|null $iconName
	 * @param string $iconType
	 * @param string $additionalClassNames Additional classes
	 * @param string $iconPrefix either `wikimedia` or `minerva`
	 * @return $this
	 */
	public function setIcon( $iconName,
		$iconType = 'before',
		$additionalClassNames = '',
		$iconPrefix = 'minerva'
	) {
		if ( $iconType === 'before' ) {
			$this->attributes['icon'] = $iconPrefix . '-' . $iconName;
		} else {
			$this->attributes['class'] .= ' ' . MinervaUI::iconClass(
				$iconName,
				$iconType,
				$additionalClassNames,
				$iconPrefix
			);
		}
		return $this;
	}

	/**
	 * Set the menu entry title
	 * @param Message $message Title message
	 * @return $this
	 */
	public function setTitle( Message $message ): self {
		$this->attributes['title'] = $message->escaped();
		return $this;
	}

	/**
	 * Set the Menu entry ID html attribute
	 * @param string $nodeID
	 * @return $this
	 */
	public function setNodeID( $nodeID ): self {
		$this->attributes['id'] = $nodeID;
		return $this;
	}

	/**
	 * Mark entry as JS only.
	 */
	public function setJSOnly() {
		$this->isJSOnly = true;
	}
}
