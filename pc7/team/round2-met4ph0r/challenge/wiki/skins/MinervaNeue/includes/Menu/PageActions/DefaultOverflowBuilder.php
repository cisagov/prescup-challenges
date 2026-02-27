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

use MediaWiki\Minerva\Menu\Entries\IMenuEntry;
use MediaWiki\Minerva\Menu\Entries\SingleMenuEntry;
use MediaWiki\Minerva\Menu\Group;
use MediaWiki\Minerva\Permissions\IMinervaPagePermissions;
use MessageLocalizer;

class DefaultOverflowBuilder implements IOverflowBuilder {

	/**
	 * @var MessageLocalizer
	 */
	private $messageLocalizer;

	/**
	 * @var IMinervaPagePermissions
	 */
	private $permissions;

	/**
	 * Initialize Default overflow menu Group
	 *
	 * @param MessageLocalizer $messageLocalizer
	 * @param IMinervaPagePermissions $permissions Minerva permissions system
	 */
	public function __construct(
		MessageLocalizer $messageLocalizer,
		IMinervaPagePermissions $permissions
	) {
		$this->messageLocalizer = $messageLocalizer;
		$this->permissions = $permissions;
	}

	/**
	 * @inheritDoc
	 */
	public function getGroup( array $toolbox, array $actions ): Group {
		$group = new Group( 'p-tb' );
		// T285567: Make sure admins can unprotect the page afterwards
		$permissionChangeAction = array_key_exists( 'unprotect', $actions ) ?
			$this->build( 'unprotect', 'unLock', 'unprotect', $actions ) :
			$this->build( 'protect', 'lock', 'protect', $actions );

		$possibleEntries = array_filter( [
			$this->build( 'info', 'infoFilled', 'info', $toolbox ),
			$this->build( 'permalink', 'link', 'permalink', $toolbox ),
			$this->build( 'backlinks', 'articleRedirect', 'whatlinkshere', $toolbox ),
			$this->build( 'wikibase', 'logoWikidata', 'wikibase', $toolbox ),
			$this->build( 'cite', 'quotes', 'citethispage', $toolbox ),
			$this->permissions->isAllowed( IMinervaPagePermissions::MOVE ) ?
				$this->build( 'move', 'move', 'move', $actions ) : null,
			$this->permissions->isAllowed( IMinervaPagePermissions::DELETE ) ?
				$this->build( 'delete', 'trash', 'delete', $actions ) : null,
			$this->permissions->isAllowed( IMinervaPagePermissions::PROTECT ) ?
				$permissionChangeAction : null
		] );

		foreach ( $possibleEntries as $menuEntry ) {
			$group->insertEntry( $menuEntry );
		}

		return $group;
	}

	/**
	 * Build the single menu entry
	 *
	 * @param string $name
	 * @param string $icon WikimediaUI icon name.
	 * @param string $toolboxIdx
	 * @param array $toolbox An array of common toolbox items from the sidebar menu
	 * @return IMenuEntry|null
	 */
	private function build( $name, $icon, $toolboxIdx, array $toolbox ) {
		$href = $toolbox[$toolboxIdx]['href'] ?? null;

		return $href ?
			SingleMenuEntry::create(
				'page-actions-overflow-' . $name,
				$this->messageLocalizer->msg( 'minerva-page-actions-' . $name )->text(),
				$href
			)->setIcon( $icon, 'before' )
			->trackClicks( $name ) : null;
	}
}
