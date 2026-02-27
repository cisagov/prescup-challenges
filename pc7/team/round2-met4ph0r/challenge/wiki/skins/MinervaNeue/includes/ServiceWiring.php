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

use MediaWiki\Config\ServiceOptions;
use MediaWiki\MediaWikiServices;
use MediaWiki\Minerva\LanguagesHelper;
use MediaWiki\Minerva\Menu\Definitions;
use MediaWiki\Minerva\Menu\Main\AdvancedMainMenuBuilder;
use MediaWiki\Minerva\Menu\Main\DefaultMainMenuBuilder;
use MediaWiki\Minerva\Menu\Main\MainMenuDirector;
use MediaWiki\Minerva\Menu\PageActions as PageActionsMenu;
use MediaWiki\Minerva\Menu\User\AdvancedUserMenuBuilder;
use MediaWiki\Minerva\Menu\User\DefaultUserMenuBuilder;
use MediaWiki\Minerva\Menu\User\UserMenuDirector;
use MediaWiki\Minerva\Permissions\IMinervaPagePermissions;
use MediaWiki\Minerva\Permissions\MinervaPagePermissions;
use MediaWiki\Minerva\SkinOptions;
use MediaWiki\Minerva\Skins\SkinMinerva;
use MediaWiki\Minerva\Skins\SkinUserPageHelper;

return [
	'Minerva.Menu.Definitions' => static function ( MediaWikiServices $services ): Definitions {
		return new Definitions(
			RequestContext::getMain(),
			$services->getSpecialPageFactory(),
			$services->getUserOptionsLookup()
		);
	},
	'Minerva.Menu.UserMenuDirector' => static function ( MediaWikiServices $services ): UserMenuDirector {
		$options = $services->getService( 'Minerva.SkinOptions' );
		$definitions = $services->getService( 'Minerva.Menu.Definitions' );

		$context = RequestContext::getMain();
		$builder = $options->get( SkinOptions::PERSONAL_MENU ) ?
			new AdvancedUserMenuBuilder(
				$context,
				$context->getUser(),
				$definitions
			) :
			new DefaultUserMenuBuilder();

		return new UserMenuDirector(
			$builder,
			$context->getSkin()
		);
	},
	'Minerva.Menu.MainDirector' => static function ( MediaWikiServices $services ): MainMenuDirector {
		$context = RequestContext::getMain();
		/** @var SkinOptions $options */
		$options = $services->getService( 'Minerva.SkinOptions' );
		$definitions = $services->getService( 'Minerva.Menu.Definitions' );
		$showMobileOptions = $options->get( SkinOptions::MOBILE_OPTIONS );
		$user = $context->getUser();
		// Add a donate link (see https://phabricator.wikimedia.org/T219793)
		$showDonateLink = $options->get( SkinOptions::SHOW_DONATE );
		$builder = $options->get( SkinOptions::MAIN_MENU_EXPANDED ) ?
			new AdvancedMainMenuBuilder( $showMobileOptions, $showDonateLink, $definitions ) :
			new DefaultMainMenuBuilder( $showMobileOptions, $showDonateLink, $user, $definitions );

		return new MainMenuDirector( $builder, $context, $services->getSpecialPageFactory() );
	},
	'Minerva.Menu.PageActionsDirector' =>
		static function ( MediaWikiServices $services ): PageActionsMenu\PageActionsDirector {
			/**
			 * @var SkinOptions $skinOptions
			 * @var SkinMinerva $skin
			 * @var SkinUserPageHelper $userPageHelper
			 */
			$skinOptions = $services->getService( 'Minerva.SkinOptions' );
			// FIXME: RequestContext should not be accessed in service container.
			$context = RequestContext::getMain();
			$title = $context->getTitle();
			if ( !$title ) {
				$title = SpecialPage::getTitleFor( 'Badtitle' );
			}
			$user = $context->getUser();
			$userPageHelper = $services->getService( 'Minerva.SkinUserPageHelper' );
			$languagesHelper = $services->getService( 'Minerva.LanguagesHelper' );

			$relevantUserPageHelper = $title->inNamespace( NS_USER_TALK ) ?
				new SkinUserPageHelper(
					$services->getUserNameUtils(),
					$context->getSkin()->getRelevantTitle()->getSubjectPage(),
					$context
				) :
				$userPageHelper;

			$watchlistManager = $services->getWatchlistManager();

			$toolbarBuilder = new PageActionsMenu\ToolbarBuilder(
				$title,
				$user,
				$context,
				$services->getService( 'Minerva.Permissions' ),
				$skinOptions,
				$relevantUserPageHelper,
				$languagesHelper,
				new ServiceOptions( PageActionsMenu\ToolbarBuilder::CONSTRUCTOR_OPTIONS,
					$services->getMainConfig() ),
				$watchlistManager
			);
			if ( $skinOptions->get( SkinOptions::TOOLBAR_SUBMENU ) ) {
				$overflowBuilder = $relevantUserPageHelper->isUserPage() ?
					new PageActionsMenu\UserNamespaceOverflowBuilder(
						$title,
						$context,
						$services->getService( 'Minerva.Permissions' ),
						$languagesHelper
					) :
					new PageActionsMenu\DefaultOverflowBuilder(
						$context,
						$services->getService( 'Minerva.Permissions' )
					);
			} else {
				$overflowBuilder = new PageActionsMenu\EmptyOverflowBuilder();
			}

			return new PageActionsMenu\PageActionsDirector(
				$toolbarBuilder,
				$overflowBuilder,
				$context
			);
		},
	'Minerva.SkinUserPageHelper' => static function ( MediaWikiServices $services ): SkinUserPageHelper {
		return new SkinUserPageHelper(
			$services->getUserNameUtils(),
			RequestContext::getMain()->getSkin()->getRelevantTitle(),
			RequestContext::getMain()
		);
	},
	'Minerva.LanguagesHelper' => static function (): LanguagesHelper {
		return new LanguagesHelper( RequestContext::getMain()->getOutput() );
	},
	'Minerva.SkinOptions' => static function (): SkinOptions {
		return new SkinOptions();
	},
	'Minerva.Permissions' => static function ( MediaWikiServices $services ): IMinervaPagePermissions {
		$permissions = new MinervaPagePermissions(
			$services->getService( 'Minerva.SkinOptions' ),
			$services->getService( 'Minerva.LanguagesHelper' ),
			$services->getPermissionManager(),
			$services->getContentHandlerFactory()
		);
		// TODO: This should not be allowed, this is basically global $wgTitle and $wgUser.
		$permissions->setContext( RequestContext::getMain() );
		return $permissions;
	}
];
