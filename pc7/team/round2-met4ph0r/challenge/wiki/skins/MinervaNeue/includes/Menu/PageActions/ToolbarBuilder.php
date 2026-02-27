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

use ExtensionRegistry;
use MediaWiki\Config\ServiceOptions;
use MediaWiki\Minerva\LanguagesHelper;
use MediaWiki\Minerva\Menu\Entries\IMenuEntry;
use MediaWiki\Minerva\Menu\Entries\LanguageSelectorEntry;
use MediaWiki\Minerva\Menu\Entries\SingleMenuEntry;
use MediaWiki\Minerva\Menu\Group;
use MediaWiki\Minerva\MinervaUI;
use MediaWiki\Minerva\Permissions\IMinervaPagePermissions;
use MediaWiki\Minerva\SkinOptions;
use MediaWiki\Minerva\Skins\SkinMinerva;
use MediaWiki\Minerva\Skins\SkinUserPageHelper;
use MediaWiki\User\UserIdentity;
use MediaWiki\Watchlist\WatchlistManager;
use MessageLocalizer;
use MWException;
use SpecialMobileHistory;
use SpecialPage;
use Title;
use User;

class ToolbarBuilder {

	/**
	 * @var User Currently logged in user
	 */
	private $user;
	/**
	 * @var Title Article title user is currently browsing
	 */
	private $title;
	/**
	 * @var MessageLocalizer Message localizer to generate localized texts
	 */
	private $messageLocalizer;
	/**
	 * @var IMinervaPagePermissions
	 */
	private $permissions;

	/**
	 * @var SkinOptions
	 */
	private $skinOptions;

	/**
	 * @var SkinUserPageHelper
	 */
	private $relevantUserPageHelper;

	/**
	 * @var LanguagesHelper
	 */
	private $languagesHelper;

	/**
	 * @var bool Correlates to $wgWatchlistExpiry feature flag.
	 */
	private $watchlistExpiryEnabled;

	/**
	 * @var WatchlistManager
	 */
	private $watchlistManager;

	/**
	 * ServiceOptions needed.
	 */
	public const CONSTRUCTOR_OPTIONS = [
		'WatchlistExpiry',
	];

	/**
	 * Build Group containing icons for toolbar
	 * @param Title $title Article title user is currently browsing
	 * @param User $user Currently logged in user
	 * @param MessageLocalizer $msgLocalizer Message localizer to generate localized texts
	 * @param IMinervaPagePermissions $permissions Minerva permissions system
	 * @param SkinOptions $skinOptions
	 * @param SkinUserPageHelper $relevantUserPageHelper User Page helper. The
	 * UserPageHelper passed should always be specific to the user page Title. If on a
	 * user talk page, UserPageHelper should be instantiated with the user page
	 * Title and NOT with the user talk page Title.
	 * @param LanguagesHelper $languagesHelper Helper to check title languages/variants
	 * @param ServiceOptions $options
	 * @param WatchlistManager $watchlistManager
	 */
	public function __construct(
		Title $title,
		User $user,
		MessageLocalizer $msgLocalizer,
		IMinervaPagePermissions $permissions,
		SkinOptions $skinOptions,
		SkinUserPageHelper $relevantUserPageHelper,
		LanguagesHelper $languagesHelper,
		ServiceOptions $options,
		WatchlistManager $watchlistManager
	) {
		$this->title = $title;
		$this->user = $user;
		$this->messageLocalizer = $msgLocalizer;
		$this->permissions = $permissions;
		$this->skinOptions = $skinOptions;
		$this->relevantUserPageHelper = $relevantUserPageHelper;
		$this->languagesHelper = $languagesHelper;
		$this->watchlistExpiryEnabled = $options->get( 'WatchlistExpiry' );
		$this->watchlistManager = $watchlistManager;
	}

	/**
	 * @return Group
	 * @throws MWException
	 */
	public function getGroup(): Group {
		$group = new Group( 'p-views' );
		$permissions = $this->permissions;
		$userPageOrUserTalkPageWithOverflowMode = $this->skinOptions->get( SkinOptions::TOOLBAR_SUBMENU )
			&& $this->relevantUserPageHelper->isUserPage();

		if ( !$userPageOrUserTalkPageWithOverflowMode && $permissions->isAllowed(
			IMinervaPagePermissions::SWITCH_LANGUAGE ) ) {
			$group->insertEntry( new LanguageSelectorEntry(
				$this->title,
				$this->languagesHelper->doesTitleHasLanguagesOrVariants( $this->title ),
				$this->messageLocalizer,
				true
			) );
		}

		if ( $permissions->isAllowed( IMinervaPagePermissions::WATCH ) ) {
			$group->insertEntry( $this->createWatchPageAction() );
		}

		if ( $permissions->isAllowed( IMinervaPagePermissions::HISTORY ) ) {
			$group->insertEntry( $this->getHistoryPageAction() );
		}

		$isUserPage = $this->relevantUserPageHelper->isUserPage();
		$isUserPageAccessible = $this->relevantUserPageHelper->isUserPageAccessibleToCurrentUser();
		if ( $isUserPage && $isUserPageAccessible ) {
			// T235681: Contributions icon should be added to toolbar on user pages
			// and user talk pages for all users
			$user = $this->relevantUserPageHelper->getPageUser();
			$group->insertEntry( $this->createContributionsPageAction( $user ) );
		}

		// We want the edit icon/action always to be the last element on the toolbar list
		if ( $permissions->isAllowed( IMinervaPagePermissions::CONTENT_EDIT ) ) {
			$group->insertEntry( $this->createEditPageAction() );
		}
		return $group;
	}

	/**
	 * Create Contributions page action visible on user pages or user talk pages
	 * for given $user
	 *
	 * @param UserIdentity $user Determines what the contribution page action will link to
	 * @return IMenuEntry
	 */
	protected function createContributionsPageAction( UserIdentity $user ): IMenuEntry {
		$label = $this->messageLocalizer->msg( 'mobile-frontend-user-page-contributions' );

		$entry = new SingleMenuEntry(
			'page-actions-contributions',
			$label->escaped(),
			SpecialPage::getTitleFor( 'Contributions', $user->getName() )->getLocalURL() );
		$entry->setTitle( $label )
			->trackClicks( 'contributions' )
			->setIcon( 'userContributions', 'element',
				'mw-ui-icon-with-label-desktop'
			);

		return $entry;
	}

	/**
	 * Creates the "edit" page action: the well-known pencil icon that, when tapped, will open an
	 * editor with the lead section loaded.
	 *
	 * @return IMenuEntry An edit page actions menu entry
	 * @throws MWException
	 * @throws \Exception
	 */
	protected function createEditPageAction(): IMenuEntry {
		$title = $this->title;

		$editArgs = [ 'action' => 'edit' ];
		if ( $title->isWikitextPage() ) {
			// If the content model is wikitext we'll default to editing the lead section.
			// Full wikitext editing is hard on mobile devices.
			$editArgs['section'] = SkinMinerva::LEAD_SECTION_NUMBER;
		}

		$editOrCreate = $this->permissions->isAllowed( IMinervaPagePermissions::EDIT_OR_CREATE );

		$entry = new SingleMenuEntry(
			'page-actions-edit',
			$this->messageLocalizer->msg( 'mobile-frontend-editor-edit' )->escaped(),
			$title->getLocalURL( $editArgs ),
			'edit-page'
		);
		$entry->setIcon( $editOrCreate ? 'edit-base20' : 'editLock-base20',
			'element', 'mw-ui-icon-with-label-desktop', 'wikimedia' )
			->trackClicks( 'edit' )
			->setTitle( $this->messageLocalizer->msg( 'mobile-frontend-pageaction-edit-tooltip' ) )
			->setNodeID( 'ca-edit' );
		return $entry;
	}

	/**
	 * Creates the "watch" or "unwatch" action: the well-known star icon that, when tapped, will
	 * add the page to or remove the page from the user's watchlist; or, if the user is logged out,
	 * will direct the user's UA to Special:Login.
	 *
	 * @return IMenuEntry An watch/unwatch page actions menu entry
	 * @throws MWException
	 */
	protected function createWatchPageAction(): IMenuEntry {
		$isWatched = $this->user->isRegistered() &&
			$this->watchlistManager->isWatched( $this->user, $this->title );
		$isTempWatched = $this->watchlistExpiryEnabled &&
			$isWatched &&
			$this->watchlistManager->isTempWatched( $this->user, $this->title );
		$newModeToSet = $isWatched ? 'unwatch' : 'watch';
		$href = $this->user->isRegistered()
			? $this->title->getLocalURL( [ 'action' => $newModeToSet ] )
			: $this->getLoginUrl( [ 'returnto' => $this->title ] );

		if ( $isWatched ) {
			$msg = $this->messageLocalizer->msg( 'unwatch' );
			$icon = $isTempWatched ? 'halfStar-progressive' : 'unStar-progressive';
		} else {
			$msg = $this->messageLocalizer->msg( 'watch' );
			$icon = 'star-base20';
		}

		$iconClass = MinervaUI::iconClass(
			$icon,
			'element',
			'mw-ui-icon-with-label-desktop watch-this-article',
			'wikimedia'
		);

		if ( $isTempWatched ) {
			$iconClass .= ' temp-watched';
		} elseif ( $isWatched ) {
			$iconClass .= ' watched';
		}

		$entry = new SingleMenuEntry(
			'page-actions-watch',
			$msg->text(),
			$href,
			$iconClass . ' mw-watchlink'
		);
		return $entry->trackClicks( $newModeToSet )
			->setTitle( $msg )
			->setNodeID( 'ca-watch' );
	}

	/**
	 * Creates a history action: An icon that links to the mobile history page.
	 *
	 * @return IMenuEntry A menu entry object that represents a map of HTML attributes
	 * and a 'text' property to be used with the pageActionMenu.mustache template.
	 * @throws MWException
	 */
	protected function getHistoryPageAction(): IMenuEntry {
		$entry = new SingleMenuEntry(
			'page-actions-history',
			$this->messageLocalizer->msg( 'minerva-page-actions-history' )->escaped(),
			$this->getHistoryUrl( $this->title )
		);
		$entry->setIcon( 'history-base20', 'element', 'mw-ui-icon-with-label-desktop', 'wikimedia' )
			->trackClicks( 'history' );
		return $entry;
	}

	/**
	 * Get the URL for the history page for the given title using Special:History
	 * when available.
	 * FIXME: temporary duplicated code, same as SkinMinerva::getHistoryUrl()
	 * @param Title $title The Title object of the page being viewed
	 * @return string
	 * @throws MWException
	 */
	protected function getHistoryUrl( Title $title ) {
		return ExtensionRegistry::getInstance()->isLoaded( 'MobileFrontend' ) &&
			   SpecialMobileHistory::shouldUseSpecialHistory( $title, $this->user ) ?
			SpecialPage::getTitleFor( 'History', $title )->getLocalURL() :
			$title->getLocalURL( [ 'action' => 'history' ] );
	}

	/**
	 * Prepares a url to the Special:UserLogin with query parameters
	 * @param array $query
	 * @return string
	 * @throws MWException
	 */
	private function getLoginUrl( $query ) {
		return SpecialPage::getTitleFor( 'Userlogin' )->getLocalURL( $query );
	}
}
