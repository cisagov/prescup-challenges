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
 *
 * @file
 */

namespace MediaWiki\Minerva\Menu\Main;

use MediaWiki\Minerva\Menu\Definitions;
use MediaWiki\Minerva\Menu\Entries\SingleMenuEntry;
use MediaWiki\Minerva\Menu\Group;
use MediaWiki\User\UserIdentity;
use MWException;

/**
 * Used to build default (available for everyone by default) main menu
 */
final class DefaultMainMenuBuilder implements IMainMenuBuilder {

	/**
	 * @var bool
	 */
	private $showMobileOptions;

	/**
	 * @var bool
	 */
	private $showDonateLink;

	/**
	 * Currently logged in user
	 * @var UserIdentity
	 */
	private $user;

	/**
	 * @var Definitions
	 */
	private $definitions;

	/**
	 * Initialize the Default Main Menu builder
	 *
	 * @param bool $showMobileOptions Show MobileOptions instead of Preferences
	 * @param bool $showDonateLink whether to show the donate link
	 * @param UserIdentity $user The current user
	 * @param Definitions $definitions A menu items definitions set
	 */
	public function __construct( $showMobileOptions, $showDonateLink, UserIdentity $user, Definitions $definitions ) {
		$this->showMobileOptions = $showMobileOptions;
		$this->showDonateLink = $showDonateLink;
		$this->user = $user;
		$this->definitions = $definitions;
	}

	/**
	 * @inheritDoc
	 */
	public function getDiscoveryGroup( array $navigationTools ): Group {
		return BuilderUtil::getDiscoveryTools( $this->definitions, $navigationTools );
	}

	/**
	 * @inheritDoc
	 */
	public function getDonateGroup(): Group {
		return BuilderUtil::getDonateGroup( $this->definitions, $this->showDonateLink );
	}

	/**
	 * @inheritDoc
	 */
	public function getInteractionToolsGroup(): Group {
		return new Group( 'p-interaction' );
	}

	/**
	 * @inheritDoc
	 * @throws MWException
	 */
	public function getSiteLinks(): Group {
		return BuilderUtil::getSiteLinks( $this->definitions );
	}

	/**
	 * Builds the anonymous settings group.
	 *
	 * @inheritDoc
	 */
	public function getSettingsGroup(): Group {
		$group = new Group( 'pt-preferences' );
		if ( $this->showMobileOptions && !$this->user->isRegistered() ) {
			$this->definitions->insertMobileOptionsItem( $group );
		}
		return $group;
	}

	/**
	 * Builds the personal tools menu item group.
	 *
	 * ... by adding the Watchlist, Settings, and Log{in,out} menu items in the given order.
	 *
	 * @inheritDoc
	 */
	public function getPersonalToolsGroup( array $personalTools ): Group {
		$group = new Group( 'p-personal' );

		// special casing for now to support Extension:GrowthExperiments
		$userpage = $personalTools[ 'userpage' ] ?? null;

		// Check if it exists. In future Extension:GrowthExperiments can unset
		// this and replace it with homepage key.
		if ( $userpage ) {
			$this->definitions->insertAuthMenuItem( $group );
		}

		// Note `homepage` is reserved for Extension:GrowthExperiments usage
		$include = [ 'homepage', 'login', 'watchlist',
			'mycontris', 'preferences', 'logout' ];
		$trackingKeyOverrides = [
			'watchlist' => 'unStar',
			'mycontris' => 'contributions',
		];

		foreach ( $include as $key ) {
			$item = $personalTools[ $key ] ?? null;
			if ( $item ) {
				// Substitute preference if $showMobileOptions is set.
				if ( $this->showMobileOptions && $key === 'preferences' ) {
					$this->definitions->insertMobileOptionsItem( $group );
				} else {
					$icon = $item['icon'] ?? null;
					$entry = SingleMenuEntry::create(
						$key,
						$item['text'],
						$item['href'],
						$item['class'] ?? '',
						$icon
					);

					// override tracking key where key mismatch
					if ( array_key_exists( $key, $trackingKeyOverrides ) ) {
						$entry->trackClicks( $trackingKeyOverrides[ $key ] );
					}
					$group->insertEntry( $entry );
				}
			}
		}
		return $group;
	}
}
