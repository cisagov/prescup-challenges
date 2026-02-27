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
namespace MediaWiki\Minerva\Permissions;

use Config;
use ConfigException;
use ContentHandler;
use IContextSource;
use MediaWiki\Content\IContentHandlerFactory;
use MediaWiki\MediaWikiServices;
use MediaWiki\Minerva\LanguagesHelper;
use MediaWiki\Minerva\SkinOptions;
use MediaWiki\Permissions\PermissionManager;
use Title;
use User;

/**
 * A wrapper for all available Minerva permissions.
 */
final class MinervaPagePermissions implements IMinervaPagePermissions {
	/**
	 * @var Title Current page title
	 */
	private $title;
	/**
	 * @var Config Extension config
	 */
	private $config;

	/**
	 * @var User
	 */
	private $user;

	/**
	 * @var ContentHandler
	 */
	private $contentHandler;

	/**
	 * @var SkinOptions Minerva skin options
	 */
	private $skinOptions;

	/**
	 * @var LanguagesHelper
	 */
	private $languagesHelper;

	/**
	 * @var PermissionManager
	 */
	private $permissionManager;

	/**
	 * @var IContentHandlerFactory
	 */
	private $contentHandlerFactory;

	/**
	 * Initialize internal Minerva Permissions system
	 * @param SkinOptions $skinOptions
	 * @param LanguagesHelper $languagesHelper
	 * @param PermissionManager $permissionManager
	 * @param IContentHandlerFactory $contentHandlerFactory
	 */
	public function __construct(
		SkinOptions $skinOptions,
		LanguagesHelper $languagesHelper,
		PermissionManager $permissionManager,
		IContentHandlerFactory $contentHandlerFactory
	) {
		$this->skinOptions = $skinOptions;
		$this->languagesHelper = $languagesHelper;
		$this->permissionManager = $permissionManager;
		$this->contentHandlerFactory = $contentHandlerFactory;
	}

	/**
	 * @param IContextSource $context
	 * @return $this
	 */
	public function setContext( IContextSource $context ) {
		$this->title = $context->getTitle();
		$this->config = $context->getConfig();
		$this->user = $context->getUser();
		// Title may be undefined in certain contexts (T179833)
		// TODO: Check if this is still true if we always pass a context instead of using global one
		if ( $this->title ) {
			$this->contentHandler = $this->contentHandlerFactory->getContentHandler(
				$this->title->getContentModel()
			);
		}
		return $this;
	}

	/**
	 * Gets whether or not the action is allowed.
	 *
	 * Actions isn't allowed when:
	 * <ul>
	 *   <li>the user is on the main page</li>
	 * </ul>
	 *
	 * The "edit" action is not allowed if editing is not possible on the page
	 * @see method isCurrentPageContentModelEditable
	 *
	 * The "switch-language" is allowed if there are interlanguage links on the page,
	 * or <code>$wgMinervaAlwaysShowLanguageButton</code> is truthy.
	 *
	 * @inheritDoc
	 * @throws ConfigException
	 */
	public function isAllowed( $action ) {
		global $wgHideInterlanguageLinks;

		if ( !$this->title ) {
			return false;
		}

		// T206406: Enable "Talk" or "Discussion" button on Main page, also, not forgetting
		// the "switch-language" button. But disable "edit" and "watch" actions.
		if ( $this->title->isMainPage() ) {
			if ( $action === self::SWITCH_LANGUAGE ) {
				return !$wgHideInterlanguageLinks;
			}
			// Only the talk page is allowed on the main page provided user is registered.
			// talk page permission is disabled on mobile for anons
			// https://phabricator.wikimedia.org/T54165
			return $action === self::TALK && $this->user->isRegistered();
		}

		if ( $action === self::TALK ) {
			return (
				$this->title->isTalkPage() ||
				$this->title->canHaveTalkPage()
			);
		}

		if ( $action === self::HISTORY && $this->title->exists() ) {
			return $this->skinOptions->get( SkinOptions::HISTORY_IN_PAGE_ACTIONS );
		}

		if ( $action === SkinOptions::TOOLBAR_SUBMENU ) {
			return $this->skinOptions->get( SkinOptions::TOOLBAR_SUBMENU );
		}

		if ( $action === self::EDIT_OR_CREATE ) {
			return $this->canEditOrCreate();
		}

		if ( $action === self::CONTENT_EDIT ) {
			return $this->isCurrentPageContentModelEditable();
		}

		if ( $action === self::WATCH ) {
			return MediaWikiServices::getInstance()->getWatchlistManager()->isWatchable( $this->title )
				? $this->user->isAllowedAll( 'viewmywatchlist', 'editmywatchlist' )
				: false;
		}

		if ( $action === self::SWITCH_LANGUAGE ) {
			if ( $wgHideInterlanguageLinks ) {
				return false;
			}
			return $this->languagesHelper->doesTitleHasLanguagesOrVariants( $this->title ) ||
				$this->config->get( 'MinervaAlwaysShowLanguageButton' );
		}

		if ( $action === self::MOVE ) {
			return $this->canMove();
		}

		if ( $action === self::DELETE ) {
			return $this->canDelete();
		}

		if ( $action === self::PROTECT ) {
			return $this->canProtect();
		}

		// Unknown action has been passed.
		return false;
	}

	/**
	 * @inheritDoc
	 */
	public function isTalkAllowed() {
		return $this->isAllowed( self::TALK );
	}

	/**
	 * Checks whether the editor can handle the existing content handler type.
	 *
	 * @return bool
	 */
	protected function isCurrentPageContentModelEditable() {
		return $this->contentHandler
			&& $this->contentHandler->supportsDirectEditing()
			&& $this->contentHandler->supportsDirectApiEditing();
	}

	/**
	 * Returns true if $title page exists and is editable or is creatable by $user as determined by
	 * quick checks.
	 * @return bool
	 */
	private function canEditOrCreate() {
		if ( !$this->title ) {
			return false;
		}

		$userQuickEditCheck =
			$this->permissionManager->userCan(
				'edit', $this->user, $this->title, PermissionManager::RIGOR_QUICK
			) && (
				$this->title->exists() ||
				$this->permissionManager->userCan(
					'create', $this->user, $this->title, PermissionManager::RIGOR_QUICK
				)
			);
		$blocked = $this->user->isRegistered() ? $this->permissionManager->isBlockedFrom(
			$this->user, $this->title, true
		) : false;
		return $this->isCurrentPageContentModelEditable() && $userQuickEditCheck && !$blocked;
	}

	/**
	 * Checks whether the user has the permissions to move the current page.
	 *
	 * @return bool
	 */
	private function canMove() {
		if ( !$this->title ) {
			return false;
		}

		return $this->permissionManager->quickUserCan( 'move', $this->user, $this->title )
			&& $this->title->exists();
	}

	/**
	 * Checks whether the user has the permissions to delete the current page.
	 *
	 * @return bool
	 */
	private function canDelete() {
		if ( !$this->title ) {
			return false;
		}

		return $this->permissionManager->quickUserCan( 'delete', $this->user, $this->title )
			&& $this->title->exists();
	}

	/**
	 * Checks whether the user has the permissions to change the protections status of the current page.
	 *
	 * @return bool
	 */
	private function canProtect() {
		if ( !$this->title ) {
			return false;
		}

		return $this->permissionManager->quickUserCan( 'protect', $this->user, $this->title )
			&& $this->title->exists();
	}
}
