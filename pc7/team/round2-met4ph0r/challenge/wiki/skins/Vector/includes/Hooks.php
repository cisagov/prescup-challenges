<?php

namespace MediaWiki\Skins\Vector;

use Config;
use IContextSource;
use MediaWiki\Auth\Hook\LocalUserCreatedHook;
use MediaWiki\Hook\MakeGlobalVariablesScriptHook;
use MediaWiki\Hook\OutputPageBodyAttributesHook;
use MediaWiki\Hook\RequestContextCreateSkinHook;
use MediaWiki\MediaWikiServices;
use MediaWiki\Preferences\Hook\GetPreferencesHook;
use MediaWiki\ResourceLoader as RL;
use MediaWiki\ResourceLoader\Hook\ResourceLoaderSiteModulePagesHook;
use MediaWiki\ResourceLoader\Hook\ResourceLoaderSiteStylesModulePagesHook;
use MediaWiki\Skins\Hook\SkinPageReadyConfigHook;
use OutputPage;
use RuntimeException;
use Skin;
use SkinTemplate;
use Title;
use User;

/**
 * Presentation hook handlers for Vector skin.
 *
 * Hook handler method names should be in the form of:
 *	on<HookName>()
 * @package Vector
 * @internal
 */
class Hooks implements
	GetPreferencesHook,
	LocalUserCreatedHook,
	MakeGlobalVariablesScriptHook,
	OutputPageBodyAttributesHook,
	ResourceLoaderSiteModulePagesHook,
	ResourceLoaderSiteStylesModulePagesHook,
	RequestContextCreateSkinHook,
	SkinPageReadyConfigHook
{
	/**
	 * Checks if the current skin is a variant of Vector
	 *
	 * @param string $skinName
	 * @return bool
	 */
	private static function isVectorSkin( string $skinName ): bool {
		return (
			$skinName === Constants::SKIN_NAME_LEGACY ||
			$skinName === Constants::SKIN_NAME_MODERN
		);
	}

	/**
	 * @param Config $config
	 * @return array
	 */
	private static function getActiveABTest( $config ) {
		$ab = $config->get(
			Constants::CONFIG_WEB_AB_TEST_ENROLLMENT
		);
		if ( count( $ab ) === 0 ) {
			// If array is empty then no experiment and need to validate.
			return $ab;
		}
		if ( !array_key_exists( 'buckets', $ab ) ) {
			throw new RuntimeException( 'Invalid VectorWebABTestEnrollment value: Must contain buckets key.' );
		}
		if ( !array_key_exists( 'unsampled', $ab['buckets'] ) ) {
			throw new RuntimeException( 'Invalid VectorWebABTestEnrollment value: Must define an `unsampled` bucket.' );
		} else {
			// check bucket values.
			foreach ( $ab['buckets'] as $bucketName => $bucketDefinition ) {
				if ( !is_array( $bucketDefinition ) ) {
					throw new RuntimeException( 'Invalid VectorWebABTestEnrollment value: Buckets should be arrays' );
				}
				$samplingRate = $bucketDefinition['samplingRate'];
				if ( is_string( $samplingRate ) ) {
					throw new RuntimeException(
						'Invalid VectorWebABTestEnrollment value: Sampling rate should be number between 0 and 1.'
					);
				}
			}
		}

		return $ab;
	}

	/**
	 * Passes config variables to Vector (modern) ResourceLoader module.
	 * @param RL\Context $context
	 * @param Config $config
	 * @return array
	 */
	public static function getVectorResourceLoaderConfig(
		RL\Context $context,
		Config $config
	) {
		return [
			'wgVectorSearchHost' => $config->get( 'VectorSearchHost' ),
			'wgVectorWebABTestEnrollment' => self::getActiveABTest( $config ),
		];
	}

	/**
	 * Generates config variables for skins.vector.search Resource Loader module (defined in
	 * skin.json).
	 *
	 * @param RL\Context $context
	 * @param Config $config
	 * @return array<string,mixed>
	 */
	public static function getVectorSearchResourceLoaderConfig(
		RL\Context $context,
		Config $config
	): array {
		$result = $config->get( 'VectorWvuiSearchOptions' );
		$result['highlightQuery'] =
			VectorServices::getLanguageService()->canWordsBeSplitSafely( $context->getLanguage() );

		return $result;
	}

	/**
	 * SkinPageReadyConfig hook handler
	 *
	 * Replace searchModule provided by skin.
	 *
	 * @since 1.35
	 * @param RL\Context $context
	 * @param mixed[] &$config Associative array of configurable options
	 * @return void This hook must not abort, it must return no value
	 */
	public function onSkinPageReadyConfig(
		RL\Context $context,
		array &$config
	): void {
		// It's better to exit before any additional check
		if ( !self::isVectorSkin( $context->getSkin() ) ) {
			return;
		}

		// Tell the `mediawiki.page.ready` module not to wire up search.
		// This allows us to use the new Vue implementation.
		// Context has no knowledge of legacy / modern Vector
		// and from its point of view they are the same thing.
		// Please see the modules `skins.vector.js` and `skins.vector.legacy.js`
		// for the wire up of search.
		// The related method self::getVectorResourceLoaderConfig handles which
		// search to load.
		$config['search'] = false;
	}

	/**
	 * Transforms watch item inside the action navigation menu
	 *
	 * @param array &$content_navigation
	 */
	private static function updateActionsMenu( &$content_navigation ) {
		$key = null;
		if ( isset( $content_navigation['actions']['watch'] ) ) {
			$key = 'watch';
		}
		if ( isset( $content_navigation['actions']['unwatch'] ) ) {
			$key = 'unwatch';
		}

		// Promote watch link from actions to views and add an icon
		if ( $key !== null ) {
			self::appendClassToItem(
				$content_navigation['actions'][$key]['class'],
				[ 'icon' ]
			);
			$content_navigation['views'][$key] = $content_navigation['actions'][$key];
			unset( $content_navigation['actions'][$key] );
		}
	}

	/**
	 * Adds class to a property
	 *
	 * @param array &$item to update
	 * @param array|string $classes to add to the item
	 */
	private static function appendClassToItem( &$item, $classes ) {
		$existingClasses = $item;

		if ( is_array( $existingClasses ) ) {
			// Treat as array
			$newArrayClasses = is_array( $classes ) ? $classes : [ trim( $classes ) ];
			$item = array_merge( $existingClasses, $newArrayClasses );
		} elseif ( is_string( $existingClasses ) ) {
			// Treat as string
			$newStrClasses = is_string( $classes ) ? trim( $classes ) : implode( ' ', $classes );
			$item .= ' ' . $newStrClasses;
		} else {
			// Treat as whatever $classes is
			$item = $classes;
		}

		if ( is_string( $item ) ) {
			$item = trim( $item );
		}
	}

	/**
	 * Updates personal navigation menu (user links) dropdown for modern Vector:
	 *  - Adds icons
	 *  - Makes user page and watchlist collapsible
	 *
	 * @param SkinTemplate $sk
	 * @param array &$content_navigation
	 */
	private static function updateUserLinksDropdownItems( $sk, &$content_navigation ) {
		// For logged-in users in modern Vector, rearrange some links in the personal toolbar.
		$user = $sk->getUser();
		$isTemp = $user->isTemp();
		$isRegistered = $user->isRegistered();
		if ( $isTemp ) {
			if ( isset( $content_navigation['user-page']['tmpuserpage'] ) ) {
				$content_navigation['user-page']['tmpuserpage']['collapsible'] = true;
				$content_navigation['user-page']['tmpuserpage'] =
					self::updateMenuItemData( $content_navigation['user-page']['tmpuserpage'] );
			}
			if ( isset( $content_navigation['user-menu']['tmpuserpage'] ) ) {
				$content_navigation['user-menu']['tmpuserpage']['collapsible'] = true;
				$content_navigation['user-menu']['tmpuserpage'] =
					self::updateMenuItemData( $content_navigation['user-menu']['tmpuserpage'] );
			}
		} elseif ( $isRegistered ) {
			// Remove user page from personal menu dropdown for logged in use
			$content_navigation['user-menu']['userpage']['collapsible'] = true;
			// watchlist may be disabled if $wgGroupPermissions['*']['viewmywatchlist'] = false;
			// See [[phab:T299671]]
			if ( isset( $content_navigation['user-menu']['watchlist'] ) ) {
				$content_navigation['user-menu']['watchlist']['collapsible'] = true;
			}
			// Remove logout link from user-menu and recreate it in SkinVector,
			unset( $content_navigation['user-menu']['logout'] );
		}

		if ( $isRegistered ) {
			// Prefix user link items with associated icon.
			// Don't show icons for anon menu items (besides login and create account).
			// Loop through each menu to check/append its link classes.
			self::updateMenuItems( $content_navigation, 'user-menu' );
		} else {
			// Remove "Not logged in" from personal menu dropdown for anon users.
			unset( $content_navigation['user-menu']['anonuserpage'] );
		}

		if ( !$isRegistered || $isTemp ) {
			// "Create account" link is handled manually by Vector
			unset( $content_navigation['user-menu']['createaccount'] );
			// "Login" link is handled manually by Vector
			unset( $content_navigation['user-menu']['login'] );
			// Remove duplicate "Login" link added by SkinTemplate::buildPersonalUrls if group read permissions
			// are set to false.
			unset( $content_navigation['user-menu']['login-private'] );
		}
	}

	/**
	 * Populates 'vector-user-menu-overflow' bucket for modern Vector with modified personal navigation (user links)
	 * menu items, including 'notification', 'user-interface-preferences', 'user-page', 'vector-user-menu-overflow'
	 *
	 * @param SkinTemplate $sk
	 * @param array &$content_navigation
	 */
	private static function updateUserLinksOverflowItems( $sk, &$content_navigation ) {
		$overflow = 'vector-user-menu-overflow';
		$content_navigation[$overflow] = [];

		// Logged in and logged out overflow items
		if ( isset( $content_navigation['user-interface-preferences']['uls'] ) ) {
			$content_navigation[$overflow]['uls'] = array_merge(
				$content_navigation['user-interface-preferences']['uls'], [
				'collapsible' => true,
			] );
		}

		// Logged in overflow items
		if ( isset( $content_navigation['user-page']['userpage'] ) ) {
			$content_navigation[$overflow]['userpage'] = array_merge(
				$content_navigation['user-page']['userpage'], [
				// T312157: Style the userpage link as a blue link rather than a quiet button.
				'button' => false,
				'collapsible' => true,
				// Remove icon
				'icon' => '',
			] );
		}
		if ( isset( $content_navigation['notifications'] ) ) {
			foreach ( $content_navigation['notifications'] as $key => $data ) {
				$content_navigation[$overflow][$key] = $data;
			}
		}
		if ( isset( $content_navigation['user-menu']['watchlist'] ) ) {
			$content_navigation[$overflow]['watchlist'] = array_merge(
				$content_navigation['user-menu']['watchlist'], [
				'id' => 'pt-watchlist-2',
				'button' => true,
				'collapsible' => true,
				'text-hidden' => true,
			] );
		}

		// Anon/temp overflow items
		$user = $sk->getUser();
		$isTemp = $user->isTemp();
		$isRegistered = $user->isRegistered();
		$isCreateAccountAllowed = ( !$isRegistered || $isTemp );
		if ( isset( $content_navigation['user-menu']['createaccount'] ) && $isCreateAccountAllowed ) {
			$content_navigation[$overflow]['createaccount'] = array_merge(
				$content_navigation['user-menu']['createaccount'], [
				'id' => 'pt-createaccount-2',
				// T312157: Style the userpage link as a blue link rather than a quiet button.
				'button' => false,
				'collapsible' => true,
				// Remove icon
				'icon' => '',
			] );
		}

		self::updateMenuItems( $content_navigation, $overflow );
	}

	/**
	 * Updates personal navigation menu (user links) for modern Vector wherein user page, create account and login links
	 * are removed from the dropdown to be handled separately. In legacy Vector, the custom "user-page" bucket is
	 * removed to preserve existing behavior.
	 *
	 * @param SkinTemplate $sk
	 * @param array &$content_navigation
	 */
	private static function updateUserLinksItems( $sk, &$content_navigation ) {
		$skinName = $sk->getSkinName();
		if ( self::isSkinVersionLegacy( $skinName ) ) {
			// Remove user page from personal toolbar since it will be inside the personal menu for logged-in
			// users in legacy Vector.
			unset( $content_navigation['user-page'] );
		} else {
			self::updateUserLinksOverflowItems( $sk, $content_navigation );
			self::updateUserLinksDropdownItems( $sk, $content_navigation );
		}
	}

	/**
	 * Modifies list item to make it collapsible.
	 *
	 * @param array &$item
	 * @param string $prefix defaults to user-links-
	 */
	private static function makeMenuItemCollapsible( array &$item, string $prefix = 'user-links-' ) {
		$COLLAPSE_MENU_ITEM_CLASS = $prefix . 'collapsible-item';
		self::appendClassToItem( $item[ 'class' ], $COLLAPSE_MENU_ITEM_CLASS );
	}

	/**
	 * Make an icon
	 *
	 * @internal for use inside Vector skin.
	 * @param string $name
	 * @return string of HTML
	 */
	public static function makeIcon( $name ) {
		// Html::makeLink will pass this through rawElement
		return '<span class="mw-ui-icon mw-ui-icon-' . $name . ' mw-ui-icon-wikimedia-' . $name . '"></span>';
	}

	/**
	 * Update template data to include classes and html that handle buttons, icons, and collapsible items.
	 *
	 * @internal for use inside Vector skin.
	 * @param array $item data to update
	 * @param string $buttonClassProp property to append button classes
	 * @param string $iconHtmlProp property to set icon HTML
	 * @return array $item Updated data
	 */
	private static function updateItemData( $item, $buttonClassProp, $iconHtmlProp ) {
		$hasButton = $item['button'] ?? false;
		$hideText = $item['text-hidden'] ?? false;
		$isCollapsible = $item['collapsible'] ?? false;
		$icon = $item['icon'] ?? '';
		unset( $item['button'] );
		unset( $item['icon'] );
		unset( $item['text-hidden'] );
		unset( $item['collapsible'] );

		if ( $isCollapsible ) {
			self::makeMenuItemCollapsible( $item );
		}
		if ( $hasButton ) {
			self::appendClassToItem( $item[ $buttonClassProp ], [ 'mw-ui-button', 'mw-ui-quiet' ] );
		}
		if ( $icon ) {
			if ( $hideText ) {
				$iconElementClasses = [ 'mw-ui-icon', 'mw-ui-icon-element',
					// Some extensions declare icons without the wikimedia- prefix. e.g. Echo
					'mw-ui-icon-' . $icon,
					// FIXME: Some icon names are prefixed with `wikimedia-`.
					// We should seek to remove all these instances.
					'mw-ui-icon-wikimedia-' . $icon
				];
				self::appendClassToItem( $item[ $buttonClassProp ], $iconElementClasses );
			} else {
				$item[ $iconHtmlProp ] = self::makeIcon( $icon );
			}
		}
		return $item;
	}

	/**
	 * Updates template data for Vector dropdown menus.
	 *
	 * @param array $item Menu data to update
	 * @return array $item Updated menu data
	 */
	public static function updateDropdownMenuData( $item ) {
		$buttonClassProp = 'heading-class';
		$iconHtmlProp = 'html-vector-heading-icon';
		return self::updateItemData( $item, $buttonClassProp, $iconHtmlProp );
	}

	/**
	 * Updates template data for Vector link items.
	 *
	 * @param array $item link data to update
	 * @return array $item Updated link data
	 */
	public static function updateLinkData( $item ) {
		$buttonClassProp = 'class';
		$iconHtmlProp = 'link-html';
		return self::updateItemData( $item, $buttonClassProp, $iconHtmlProp );
	}

	/**
	 * Updates template data for Vector menu items.
	 *
	 * @param array $item menu item data to update
	 * @return array $item Updated menu item data
	 */
	public static function updateMenuItemData( $item ) {
		$buttonClassProp = 'link-class';
		$iconHtmlProp = 'link-html';
		return self::updateItemData( $item, $buttonClassProp, $iconHtmlProp );
	}

	/**
	 * Updates user interface preferences for modern Vector to upgrade icon/button menu items.
	 *
	 * @param array &$content_navigation
	 * @param string $menu identifier
	 */
	private static function updateMenuItems( &$content_navigation, $menu ) {
		foreach ( $content_navigation[$menu] as $key => $item ) {
			$content_navigation[$menu][$key] = self::updateMenuItemData( $item );
		}
	}

	/**
	 * Vector 2022 only:
	 * Creates an additional menu that will be injected inside the more (cactions)
	 * dropdown menu. This menu is a clone of `views` and this menu will only be
	 * shown at low resolutions (when the `views` menu is hidden).
	 *
	 * An additional menu is used instead of adding to the existing cactions menu
	 * so that the emptyPortlet logic for that menu is preserved and the cactions menu
	 * is not shown at large resolutions when empty (e.g. all items including collapsed
	 * items are hidden).
	 *
	 * @param array &$content_navigation
	 */
	private static function createMoreOverflowMenu( &$content_navigation ) {
		$clonedViews = [];
		foreach ( array_keys( $content_navigation['views'] ?? [] ) as $key ) {
			$newItem = $content_navigation['views'][$key];
			self::makeMenuItemCollapsible(
				$newItem,
				'vector-more-'
			);
			$clonedViews['more-' . $key] = $newItem;
		}
		// Inject collapsible menu items ahead of existing actions.
		$content_navigation['views-overflow'] = $clonedViews;
	}

	/**
	 * Upgrades Vector's watch action to a watchstar.
	 * This is invoked inside SkinVector, not via skin registration, as skin hooks
	 * are not guaranteed to run last.
	 * This can possibly be revised based on the outcome of T287622.
	 *
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/SkinTemplateNavigation
	 * @param SkinTemplate $sk
	 * @param array &$content_navigation
	 */
	public static function onSkinTemplateNavigation( $sk, &$content_navigation ) {
		$title = $sk->getRelevantTitle();

		$skinName = $sk->getSkinName();
		if ( self::isVectorSkin( $skinName ) ) {
			if (
				$sk->getConfig()->get( 'VectorUseIconWatch' ) &&
				$title && $title->canExist()
			) {
				self::updateActionsMenu( $content_navigation );
			}

			self::updateUserLinksItems( $sk, $content_navigation );
		}
		if ( $skinName === Constants::SKIN_NAME_MODERN ) {
			self::createMoreOverflowMenu( $content_navigation );
		}
	}

	/**
	 * Adds MediaWiki:Vector.css as the skin style that controls classic Vector.
	 *
	 * @param string $skin
	 * @param array &$pages
	 */
	public function onResourceLoaderSiteStylesModulePages( $skin, &$pages ): void {
		if ( $skin === Constants::SKIN_NAME_MODERN ) {
			$pages['MediaWiki:Vector.css'] = [ 'type' => 'style' ];
		}
	}

	/**
	 * Adds MediaWiki:Vector.css as the skin style that controls classic Vector.
	 *
	 * @param string $skin
	 * @param array &$pages
	 */
	public function onResourceLoaderSiteModulePages( $skin, &$pages ): void {
		if ( $skin === Constants::SKIN_NAME_MODERN ) {
			$pages['MediaWiki:Vector.js'] = [ 'type' => 'script' ];
		}
	}

	/**
	 * Adds the persistent sidebar hidden API preference.
	 *
	 * @param User $user User whose preferences are being modified.
	 * @param array[] &$prefs Preferences description array, to be fed to a HTMLForm object.
	 */
	public function onGetPreferences( $user, &$prefs ): void {
		$config = MediaWikiServices::getInstance()->getMainConfig();
		$vectorPrefs = [
			Constants::PREF_KEY_SIDEBAR_VISIBLE => [
				'type' => 'api',
				'default' => $config->get(
					Constants::CONFIG_KEY_DEFAULT_SIDEBAR_VISIBLE_FOR_AUTHORISED_USER
				),
			],
		];
		$prefs += $vectorPrefs;
	}

	/**
	 * Called one time when initializing a users preferences for a newly created account.
	 *
	 * @param User $user Newly created user object.
	 * @param bool $isAutoCreated
	 */
	public function onLocalUserCreated( $user, $isAutoCreated ) {
		$config = MediaWikiServices::getInstance()->getMainConfig();
		$default = $config->get( Constants::CONFIG_KEY_DEFAULT_SKIN_VERSION_FOR_NEW_ACCOUNTS );
		if ( $default ) {
			$optionsManager = MediaWikiServices::getInstance()->getUserOptionsManager();
			$optionsManager->setOption(
				$user,
				Constants::PREF_KEY_SKIN,
				$default === Constants::SKIN_VERSION_LEGACY ?
					Constants::SKIN_NAME_LEGACY : Constants::SKIN_NAME_MODERN
			);
		}
	}

	/**
	 * Returns the necessary TOC classes.
	 *
	 * @param Skin $sk
	 * @param Config $config
	 * @return string[]
	 */
	private static function getTocClasses( Skin $sk, $config ): array {
		if ( !( $sk instanceof SkinVector22 ) ) {
			return [];
		}

		$classes = [];
		if (
			$sk->isTOCABTestEnabled() &&
			$sk->isTableOfContentsVisibleInSidebar() &&
			!$sk->getUser()->isAnon()
		) {
			$userBucket = !$sk->isUserInTocTreatmentBucket()
				? 'control'
				: 'treatment';
			$experimentConfig = $config->get( Constants::CONFIG_WEB_AB_TEST_ENROLLMENT );
			$experimentName = $experimentConfig[ 'name' ];
			$classes[] = $experimentName;
			$classes[] = "$experimentName-$userBucket";
		}

		return $classes;
	}

	/**
	 * Called when OutputPage::headElement is creating the body tag to allow skins
	 * and extensions to add attributes they might need to the body of the page.
	 *
	 * @param OutputPage $out
	 * @param Skin $sk
	 * @param string[] &$bodyAttrs
	 */
	public function onOutputPageBodyAttributes( $out, $sk, &$bodyAttrs ): void {
		$skinName = $out->getSkin()->getSkinName();
		if ( !self::isVectorSkin( $skinName ) ) {
			return;
		}
		$config = $sk->getConfig();

		// As of 2020/08/13, this CSS class is referred to by the following deployed extensions:
		//
		// - VisualEditor
		// - CodeMirror
		// - WikimediaEvents
		//
		// See https://codesearch.wmcloud.org/deployed/?q=skin-vector-legacy for an up-to-date
		// list.
		if ( self::isSkinVersionLegacy( $skinName ) ) {
			$bodyAttrs['class'] .= ' skin-vector-legacy';
		}

		$tocClasses = self::getTocClasses( $sk, $config );
		if ( $tocClasses ) {
			$bodyAttrs['class'] .= ' ' . implode( ' ', $tocClasses );
		}

		// Should we disable the max-width styling?
		if ( !self::isSkinVersionLegacy( $skinName ) && $sk->getTitle() && self::shouldDisableMaxWidth(
			$config->get( 'VectorMaxWidthOptions' ),
			$sk->getTitle(),
			$out->getRequest()->getValues()
		) ) {
			$bodyAttrs['class'] .= ' skin-vector-disable-max-width';
		}

		$featureManager = VectorServices::getFeatureManager();
		$bodyAttrs['class'] .= ' ' . implode( ' ', $featureManager->getFeatureBodyClass() );
		$bodyAttrs['class'] = trim( $bodyAttrs['class'] );
	}

	/**
	 * Temporary RequestContextCreateSkin hook handler.
	 * Switches to new Vector on certain pages.
	 *
	 * @see https://www.mediawiki.org/wiki/Manual:Hooks/RequestContextCreateSkin
	 *
	 * @param IContextSource $context The RequestContext object the skin is being created for.
	 * @param Skin|null|string &$skin A variable reference you may set a Skin instance or string
	 *                                key on to override the skin that will be used for the context.
	 * @return bool|void
	 */
	public function onRequestContextCreateSkin( $context, &$skin ) {
		if ( !$skin ) {
			// user is anonymous
			$user = $context->getUser();
			$config = $context->getConfig();
			$titles = $config->get( 'Vector2022PreviewPages' );
			$title = $context->getTitle();
			$titleText = $title ? $title->getPrefixedText() : null;
			if ( $titleText && $user->isAnon() && in_array( $titleText, $titles ) ) {
				$skin = 'vector-2022';
			}
		}
	}

	/**
	 * Per the $options configuration (for use with $wgVectorMaxWidthOptions)
	 * determine whether max-width should be disabled on the page.
	 * For the main page: Check the value of $options['exclude']['mainpage']
	 * For all other pages, the following will happen:
	 * - the array $options['include'] of canonical page names will be checked
	 *   against the current page. If a page has been listed there, function will return false
	 *   (max-width will not be  disabled)
	 * Max width is disabled if:
	 *  1) The current namespace is listed in array $options['exclude']['namespaces']
	 *  OR
	 *  2) A query string parameter matches one of the regex patterns in $exclusions['querystring'].
	 *
	 * @internal only for use inside tests.
	 * @param array $options
	 * @param Title $title
	 * @param array $requestValues
	 * @return bool
	 */
	public static function shouldDisableMaxWidth( array $options, Title $title, array $requestValues ) {
		$canonicalTitle = $title->getRootTitle();

		$inclusions = $options['include'] ?? [];
		$exclusions = $options['exclude'] ?? [];

		if ( $title->isMainPage() ) {
			// only one check to make
			return $exclusions['mainpage'] ?? false;
		} elseif ( $canonicalTitle->isSpecialPage() ) {
			$canonicalTitle->fixSpecialName();
		}

		//
		// Check the inclusions based on the canonical title
		// The inclusions are checked first as these trump any exclusions.
		//
		// Now we have the canonical title and the inclusions link we look for any matches.
		foreach ( $inclusions as $titleText ) {
			$includedTitle = Title::newFromText( $titleText );

			if ( $canonicalTitle->equals( $includedTitle ) ) {
				return false;
			}
		}

		//
		// Check the exclusions
		// If nothing matches the exclusions to determine what should happen
		//
		$excludeNamespaces = $exclusions['namespaces'] ?? [];
		// Max width is disabled on certain namespaces
		if ( $title->inNamespaces( $excludeNamespaces ) ) {
			return true;
		}
		$excludeQueryString = $exclusions['querystring'] ?? [];

		foreach ( $excludeQueryString as $param => $excludedParamPattern ) {
			$paramValue = $requestValues[$param] ?? false;
			if ( $paramValue ) {
				if ( $excludedParamPattern === '*' ) {
					// Backwards compatibility for the '*' wildcard.
					$excludedParamPattern = '.+';
				}
				return (bool)preg_match( "/$excludedParamPattern/", $paramValue );
			}
		}

		return false;
	}

	/**
	 * NOTE: Please use ResourceLoaderGetConfigVars hook instead if possible
	 * for adding config to the page.
	 * Adds config variables to JS that depend on current page/request.
	 *
	 * Adds a config flag that can disable saving the VectorSidebarVisible
	 * user preference when the sidebar menu icon is clicked.
	 *
	 * @param array &$vars Array of variables to be added into the output.
	 * @param OutputPage $out OutputPage instance calling the hook
	 */
	public function onMakeGlobalVariablesScript( &$vars, $out ): void {
		$skin = $out->getSkin();
		$skinName = $skin->getSkinName();
		if ( !self::isVectorSkin( $skinName ) ) {
			return;
		}
		$config = $out->getConfig();
		$user = $out->getUser();

		if ( $user->isRegistered() && self::isSkinVersionLegacy( $skinName ) ) {
			$vars[ 'wgVectorDisableSidebarPersistence' ] =
				$config->get(
					Constants::CONFIG_KEY_DISABLE_SIDEBAR_PERSISTENCE
				);
		}
		// Must be exposed to CentralNotice banners via mw.config
		$vars[ 'wgVector2022PreviewPages' ] = $config->get( 'Vector2022PreviewPages' );
	}

	/**
	 * Gets whether the current skin version is the legacy version.
	 * Should mirror SkinVector::isLegacy
	 *
	 * @param string $skinName hint that can be used to detect modern vector.
	 * @return bool
	 */
	private static function isSkinVersionLegacy( $skinName ): bool {
		return $skinName === Constants::SKIN_NAME_LEGACY;
	}
}
