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

namespace MediaWiki\Minerva;

use ExtensionRegistry;
use Hooks as MWHooks;
use Html;
use MediaWiki\MediaWikiServices;
use MediaWiki\Minerva\Skins\SkinMinerva;
use MediaWiki\Minerva\Skins\SkinUserPageHelper;
use MobileContext;
use MobileFormatter;
use MobileFrontend\Features\Feature;
use MobileFrontend\Features\FeaturesManager;
use OldChangesList;
use OutputPage;
use ResourceLoader;
use ResourceLoaderContext;
use RuntimeException;
use Skin;
use SpecialPage;
use User;
use Wikimedia\Services\NoSuchServiceException;

/**
 * Hook handlers for Minerva skin.
 *
 * Hook handler method names should be in the form of:
 *	on<HookName>()
 */
class Hooks {
	private const FEATURE_OVERFLOW_PAGE_ACTIONS = 'MinervaOverflowInPageActions';

	/**
	 * ResourceLoaderRegisterModules hook handler.
	 *
	 * Registers:
	 *
	 * * EventLogging schema modules, if the EventLogging extension is loaded;
	 * * Modules for the Visual Editor overlay, if the VisualEditor extension is loaded; and
	 * * Modules for the notifications overlay, if the Echo extension is loaded.
	 *
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/ResourceLoaderRegisterModules
	 *
	 * @param ResourceLoader $resourceLoader
	 */
	public static function onResourceLoaderRegisterModules( ResourceLoader $resourceLoader ) {
		if ( !ExtensionRegistry::getInstance()->isLoaded( 'MobileFrontend' ) ) {
			$resourceLoader->register( [
				'mobile.startup' => [
					'dependencies' => [ 'mediawiki.searchSuggest' ],
					'localBasePath' => dirname( __DIR__ ),
					'remoteExtPath' => 'Minerva',
					'scripts' => 'resources/mobile.startup.stub.js',
					'targets' => [ 'desktop', 'mobile' ],
				]
			] );
		}
	}

	/**
	 * Disable recent changes enhanced mode (table mode)
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/FetchChangesList
	 *
	 * @param User $user
	 * @param Skin $skin
	 * @param array &$list
	 * @param array $groups
	 * @return bool|null
	 */
	public static function onFetchChangesList( User $user, Skin $skin, &$list, $groups = [] ) {
		if ( $skin->getSkinName() === 'minerva' ) {
			// The new changes list (table-based) does not work with Minerva
			$list = new OldChangesList( $skin->getContext(), $groups );
			// returning false makes sure $list is used instead.
			return false;
		}
	}

	/**
	 * Register mobile web beta features
	 * @see https://www.mediawiki.org/wiki/
	 *  Extension:MobileFrontend/MobileFrontendFeaturesRegistration
	 *
	 * @param FeaturesManager $featureManager
	 */
	public static function onMobileFrontendFeaturesRegistration( $featureManager ) {
		$config = MediaWikiServices::getInstance()->getConfigFactory()
			->makeConfig( 'minerva' );

		try {
			$featureManager->registerFeature(
				new Feature(
					'MinervaShowCategories',
					'skin-minerva',
					$config->get( 'MinervaShowCategories' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaPageIssuesNewTreatment',
					'skin-minerva',
					$config->get( 'MinervaPageIssuesNewTreatment' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaTalkAtTop',
					'skin-minerva',
					$config->get( 'MinervaTalkAtTop' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaDonateLink',
					'skin-minerva',
					$config->get( 'MinervaDonateLink' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaHistoryInPageActions',
					'skin-minerva',
					$config->get( 'MinervaHistoryInPageActions' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					self::FEATURE_OVERFLOW_PAGE_ACTIONS,
					'skin-minerva',
					$config->get( self::FEATURE_OVERFLOW_PAGE_ACTIONS )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaAdvancedMainMenu',
					'skin-minerva',
					$config->get( 'MinervaAdvancedMainMenu' )
				)
			);
			$featureManager->registerFeature(
				new Feature(
					'MinervaPersonalMenu',
					'skin-minerva',
					$config->get( 'MinervaPersonalMenu' )
				)
			);
		} catch ( RuntimeException $e ) {
			// features already registered...
			// due to a bug it's possible for this to run twice
			// https://phabricator.wikimedia.org/T165068
		}
	}

	/**
	 * Invocation of hook SpecialPageBeforeExecute
	 *
	 * We use this hook to ensure that login/account creation pages
	 * are redirected to HTTPS if they are not accessed via HTTPS and
	 * $wgSecureLogin == true - but only when using the
	 * mobile site.
	 *
	 * @param SpecialPage $special
	 * @param string $subpage
	 */
	public static function onSpecialPageBeforeExecute( SpecialPage $special, $subpage ) {
		$name = $special->getName();
		$out = $special->getOutput();
		$skin = $out->getSkin();
		$request = $special->getRequest();

		if ( $skin instanceof SkinMinerva ) {
			switch ( $name ) {
				case 'Recentchanges':
					$isEnhancedDefaultForUser = MediaWikiServices::getInstance()
						->getUserOptionsLookup()
						->getBoolOption( $special->getUser(), 'usenewrc' );
					$enhanced = $request->getBool( 'enhanced', $isEnhancedDefaultForUser );
					if ( $enhanced ) {
						$out->addHTML( Html::warningBox(
							$special->msg( 'skin-minerva-recentchanges-warning-enhanced-not-supported' )->parse()
						) );
					}
					break;
				case 'Userlogin':
				case 'CreateAccount':
					// Add default warning message to Special:UserLogin and Special:UserCreate
					// if no warning message set.
					if (
						!$request->getVal( 'warning' ) &&
						!$special->getUser()->isRegistered() &&
						!$request->wasPosted()
					) {
						$request->setVal( 'warning', 'mobile-frontend-generic-login-new' );
					}
					break;
			}
		}
	}

	/**
	 * Set the skin options for Minerva
	 *
	 * @param MobileContext $mobileContext
	 * @param Skin $skin
	 */
	private static function setMinervaSkinOptions(
		MobileContext $mobileContext, Skin $skin
	) {
		// setSkinOptions is not available
		if ( $skin instanceof SkinMinerva
		) {
			$services = MediaWikiServices::getInstance();
			$featureManager = $services
				->getService( 'MobileFrontend.FeaturesManager' );
			$skinOptions = $services->getService( 'Minerva.SkinOptions' );
			$title = $skin->getTitle();

			// T245162 - this should only apply if the context relates to a page view.
			// Examples:
			// - parsing wikitext during an REST response
			// - a ResourceLoader response
			if ( $title !== null ) {
				// T232653: TALK_AT_TOP, HISTORY_IN_PAGE_ACTIONS, TOOLBAR_SUBMENU should
				// be true on user pages and user talk pages for all users
				//
				// For some reason using $services->getService( 'SkinUserPageHelper' )
				// here results in a circular dependency error which is why
				// SkinUserPageHelper is being instantiated instead.
				$relevantUserPageHelper = new SkinUserPageHelper(
					$services->getUserNameUtils(),
					$title->inNamespace( NS_USER_TALK ) ? $title->getSubjectPage() : $title,
					$mobileContext
				);

				$isUserPage = $relevantUserPageHelper->isUserPage();
				$isUserPageAccessible = $relevantUserPageHelper->isUserPageAccessibleToCurrentUser();
				$isUserPageOrUserTalkPage = $isUserPage && $isUserPageAccessible;
			} else {
				// If no title this must be false
				$isUserPageOrUserTalkPage = false;
			}

			$isBeta = $mobileContext->isBetaGroupMember();
			$skinOptions->setMultiple( [
				SkinOptions::SHOW_DONATE => $featureManager->isFeatureAvailableForCurrentUser( 'MinervaDonateLink' ),
				SkinOptions::TALK_AT_TOP => $isUserPageOrUserTalkPage ?
					true : $featureManager->isFeatureAvailableForCurrentUser( 'MinervaTalkAtTop' ),
				SkinOptions::BETA_MODE
					=> $isBeta,
				SkinOptions::CATEGORIES
					=> $featureManager->isFeatureAvailableForCurrentUser( 'MinervaShowCategories' ),
				SkinOptions::PAGE_ISSUES
					=> $featureManager->isFeatureAvailableForCurrentUser( 'MinervaPageIssuesNewTreatment' ),
				SkinOptions::MOBILE_OPTIONS => true,
				SkinOptions::PERSONAL_MENU => $featureManager->isFeatureAvailableForCurrentUser(
					'MinervaPersonalMenu'
				),
				SkinOptions::MAIN_MENU_EXPANDED => $featureManager->isFeatureAvailableForCurrentUser(
					'MinervaAdvancedMainMenu'
				),
				SkinOptions::HISTORY_IN_PAGE_ACTIONS => $isUserPageOrUserTalkPage ?
					true : $featureManager->isFeatureAvailableForCurrentUser( 'MinervaHistoryInPageActions' ),
				SkinOptions::TOOLBAR_SUBMENU => $isUserPageOrUserTalkPage ?
					true : $featureManager->isFeatureAvailableForCurrentUser(
						self::FEATURE_OVERFLOW_PAGE_ACTIONS
					),
				SkinOptions::TABS_ON_SPECIALS => true,
			] );
			MWHooks::run( 'SkinMinervaOptionsInit', [ $skin, $skinOptions ] );
		}
	}

	/**
	 * MobileFrontendBeforeDOM hook handler that runs before the MobileFormatter
	 * executes. We use it to determine whether or not the talk page is eligible
	 * to be simplified (we want it only to be simplified when the MobileFormatter
	 * makes expandable sections).
	 *
	 * @param MobileContext $mobileContext
	 * @param MobileFormatter $formatter
	 */
	public static function onMobileFrontendBeforeDOM(
		MobileContext $mobileContext,
		MobileFormatter $formatter
	) {
		$services = MediaWikiServices::getInstance();
		$skinOptions = $services->getService( 'Minerva.SkinOptions' );
		$skinOptions->setMultiple( [
			SkinOptions::SIMPLIFIED_TALK => true
		] );
	}

	/**
	 * UserLogoutComplete hook handler.
	 * Resets skin options if a user logout occurs - this is necessary as the
	 * RequestContextCreateSkinMobile hook runs before the UserLogout hook.
	 *
	 * @param User $user
	 */
	public static function onUserLogoutComplete( User $user ) {
		try {
			$ctx = MediaWikiServices::getInstance()->getService( 'MobileFrontend.Context' );
			self::setMinervaSkinOptions( $ctx, $ctx->getSkin() );
		} catch ( NoSuchServiceException $ex ) {
			// MobileFrontend not installed. Not important.
		}
	}

	/**
	 * BeforePageDisplayMobile hook handler.
	 *
	 * @param MobileContext $mobileContext
	 * @param Skin $skin
	 */
	public static function onRequestContextCreateSkinMobile(
		MobileContext $mobileContext, Skin $skin
	) {
		self::setMinervaSkinOptions( $mobileContext, $skin );
	}

	/**
	 * ResourceLoaderGetConfigVars hook handler.
	 * Used for setting JS variables which are pulled in dynamically with RL
	 * instead of embedded directly on the page with a script tag.
	 * These vars have a shorter cache-life than those in `getJsConfigVars`.
	 *
	 * @param array &$vars Array of variables to be added into the output of the RL startup module.
	 * @param string $skin
	 */
	public static function onResourceLoaderGetConfigVars( &$vars, $skin ) {
		if ( $skin === 'minerva' ) {
			$config = MediaWikiServices::getInstance()->getConfigFactory()
				->makeConfig( 'minerva' );
			// This is to let the UI adjust itself to a wiki that is always read-only.
			// Ignore temporary read-only on live wikis, requires heavy DB check (T233458).
			$roConf = MediaWikiServices::getInstance()->getConfiguredReadOnlyMode();
			$vars += [
				'wgMinervaABSamplingRate' => $config->get( 'MinervaABSamplingRate' ),
				'wgMinervaReadOnly' => $roConf->isReadOnly(),
			];
		}
	}

	/**
	 * The Minerva skin loads message box styles differently from core, to
	 * reduce the amount of styles on the critical path.
	 * This adds message box styles to pages that need it, to avoid loading them
	 * on pages where they are not.
	 *
	 * @param OutputPage $out
	 * @param Skin $skin
	 */
	public static function onBeforePageDisplay( OutputPage $out, Skin $skin ) {
		if ( $skin->getSkinName() === 'minerva' ) {
			self::addMessageBoxStylesToPage( $out );
		}
	}

	/**
	 * The Minerva skin loads message box styles differently from core, to
	 * reduce the amount of styles on the critical path.
	 * This adds message box styles to pages that need it, to avoid loading them
	 * on pages where they are not.
	 * The pages where they are needed are:
	 * - special pages
	 * - edit workflow (action=edit and action=submit)
	 * - when viewing old revisions
	 * - non-main namespaces for anon talk page messages
	 *
	 * @param OutputPage $out
	 */
	private static function addMessageBoxStylesToPage( OutputPage $out ) {
		$request = $out->getRequest();
		$title = $out->getTitle();
		// Warning box styles are needed when reviewing old revisions
		// and inside the fallback editor styles to action=edit page.
		$requestAction = $request->getVal( 'action' );
		$viewAction = $requestAction === null || $requestAction === 'view';

		if (
			$title->getNamespace() !== NS_MAIN ||
			$request->getText( 'oldid' ) ||
			!$viewAction
		) {
			$out->addModuleStyles( [
				'skins.minerva.messageBox.styles'
			] );
		}
	}

	/**
	 * Modifies the `<body>` element's attributes.
	 *
	 * By default, the `class` attribute is set to the output's "bodyClassName"
	 * property.
	 *
	 * @param OutputPage $out
	 * @param Skin $skin
	 * @param string[] &$bodyAttrs
	 */
	public static function onOutputPageBodyAttributes( OutputPage $out, Skin $skin, &$bodyAttrs ) {
		$classes = $out->getProperty( 'bodyClassName' );
		$skinOptions = MediaWikiServices::getInstance()->getService( 'Minerva.SkinOptions' );
		$isMinerva = $skin instanceof SkinMinerva;

		if ( $isMinerva && $skinOptions->get( SkinOptions::HISTORY_IN_PAGE_ACTIONS ) ) {
			// Class is used when page actions is modified to contain more elements
			$classes .= ' minerva--history-page-action-enabled';
		}

		if ( $isMinerva ) {
			// phan doesn't realize that $skin can only be an instance of SkinMinerva without this:
			'@phan-var SkinMinerva $skin';
			if ( $skin->isSimplifiedTalkPageEnabled() ) {
				$classes .= ' skin-minerva--talk-simplified';
			}

			$bodyAttrs['class'] .= ' ' . $classes;
		}
	}

	/**
	 * SkinPageReadyConfig hook handler
	 *
	 * Disable collapsible and sortable on page load
	 *
	 * @param ResourceLoaderContext $context
	 * @param mixed[] &$config Associative array of configurable options
	 * @return void This hook must not abort, it must return no value
	 */
	public static function onSkinPageReadyConfig(
		ResourceLoaderContext $context,
		array &$config
	) {
		if ( $context->getSkin() === 'minerva' ) {
			$config['search'] = false;
			$config['collapsible'] = false;
			$config['sortable'] = true;
			$config['selectorLogoutLink'] = 'a.menu__item--logout[data-mw="interface"]';
		}
	}
}
