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

namespace MediaWiki\Minerva\Menu\PageActions;

use MediaWiki\Minerva\LanguagesHelper;
use MediaWiki\Minerva\Menu\Entries\IMenuEntry;
use MediaWiki\Minerva\Menu\Entries\LanguageSelectorEntry;
use MediaWiki\Minerva\Menu\Entries\SingleMenuEntry;
use MediaWiki\Minerva\Menu\Group;
use MediaWiki\Minerva\Permissions\IMinervaPagePermissions;
use MessageLocalizer;
use MWException;
use Title;

class UserNamespaceOverflowBuilder implements IOverflowBuilder {

	/**
	 * @var MessageLocalizer
	 */
	private $messageLocalizer;

	/**
	 * @var Title
	 */
	private $title;

	/**
	 * @var IMinervaPagePermissions
	 */
	private $permissions;

	/**
	 * @var LanguagesHelper
	 */
	private $languagesHelper;

	/**
	 * Initialize the overflow menu visible on the User namespace
	 * @param Title $title
	 * @param MessageLocalizer $msgLocalizer
	 * @param IMinervaPagePermissions $permissions
	 * @param LanguagesHelper $languagesHelper
	 */
	public function __construct(
		Title $title,
		MessageLocalizer $msgLocalizer,
		IMinervaPagePermissions $permissions,
		LanguagesHelper $languagesHelper
	) {
		$this->title = $title;
		$this->messageLocalizer = $msgLocalizer;
		$this->permissions = $permissions;
		$this->languagesHelper = $languagesHelper;
	}

	/**
	 * @inheritDoc
	 * @throws MWException
	 */
	public function getGroup( array $toolbox, array $actions ): Group {
		$group = new Group( 'p-tb' );
		if ( $this->permissions->isAllowed( IMinervaPagePermissions::SWITCH_LANGUAGE ) ) {
			$group->insertEntry( new LanguageSelectorEntry(
				$this->title,
				$this->languagesHelper->doesTitleHasLanguagesOrVariants( $this->title ),
				$this->messageLocalizer,
				false,
				// no additional classes
				'',
				'minerva-page-actions-language-switcher'
			) );
		}

		$permissionChangeAction = array_key_exists( 'unprotect', $actions ) ?
			$this->buildFromToolbox( 'unprotect', 'unLock', 'unprotect', $actions ) :
			$this->buildFromToolbox( 'protect', 'lock', 'protect', $actions );

		$possibleEntries = array_filter( [
			$this->buildFromToolbox( 'user-groups', 'userGroup', 'userrights', $toolbox ),
			$this->buildFromToolbox( 'block', 'block', 'blockip', $toolbox ),
			$this->buildFromToolbox( 'change-block', 'block', 'changeblockip', $toolbox ),
			$this->buildFromToolbox( 'unblock', 'unBlock', 'unblockip', $toolbox ),
			$this->buildFromToolbox( 'logs', 'listBullet', 'log', $toolbox ),
			$this->buildFromToolbox( 'info', 'infoFilled', 'info', $toolbox ),
			$this->buildFromToolbox( 'permalink', 'link', 'permalink', $toolbox ),
			$this->buildFromToolbox( 'backlinks', 'articleRedirect', 'whatlinkshere', $toolbox ),
			$this->permissions->isAllowed( IMinervaPagePermissions::MOVE ) ?
				$this->buildFromToolbox( 'move', 'move', 'move', $actions ) : null,
			$this->permissions->isAllowed( IMinervaPagePermissions::DELETE ) ?
				$this->buildFromToolbox( 'delete', 'trash', 'delete', $actions ) : null,
			$this->permissions->isAllowed( IMinervaPagePermissions::PROTECT ) ?
				$permissionChangeAction : null
		] );

		foreach ( $possibleEntries as $menuEntry ) {
			$group->insertEntry( $menuEntry );
		}

		return $group;
	}

	/**
	 * Build entry based on the $toolbox element
	 *
	 * @param string $name
	 * @param string $icon Icon CSS class name.
	 * @param string $toolboxIdx
	 * @param array $toolbox An array of common toolbox items from the sidebar menu
	 * @return IMenuEntry|null
	 */
	private function buildFromToolbox( $name, $icon, $toolboxIdx, array $toolbox ) {
		return $this->build( $name, $icon, $toolbox[$toolboxIdx]['href'] ?? null );
	}

	/**
	 * Build single Menu entry
	 *
	 * @param string $name
	 * @param string $icon WikimediaUI icon name.
	 * @param string|null $href
	 * @return IMenuEntry|null
	 */
	private function build( $name, $icon, $href ) {
		return $href ?
			SingleMenuEntry::create(
				'page-actions-overflow-' . $name,
				$this->messageLocalizer->msg( 'minerva-page-actions-' . $name )->text(),
				$href
			)->setIcon( $icon, 'before' )
			->trackClicks( $name ) : null;
	}
}
