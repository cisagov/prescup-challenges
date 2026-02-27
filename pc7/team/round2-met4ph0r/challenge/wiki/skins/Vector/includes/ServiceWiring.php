<?php

/**
 * Service Wirings for Vector skin
 *
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
 * @since 1.35
 */

use MediaWiki\MediaWikiServices;
use MediaWiki\Skins\Vector\Constants;
use MediaWiki\Skins\Vector\FeatureManagement\FeatureManager;
use MediaWiki\Skins\Vector\FeatureManagement\Requirements\DynamicConfigRequirement;
use MediaWiki\Skins\Vector\FeatureManagement\Requirements\OverridableConfigRequirement;
use MediaWiki\Skins\Vector\FeatureManagement\Requirements\TableOfContentsTreatmentRequirement;

return [
	Constants::SERVICE_FEATURE_MANAGER => static function ( MediaWikiServices $services ) {
		$featureManager = new FeatureManager();

		$featureManager->registerRequirement(
			new DynamicConfigRequirement(
				$services->getMainConfig(),
				Constants::CONFIG_KEY_FULLY_INITIALISED,
				Constants::REQUIREMENT_FULLY_INITIALISED
			)
		);

		$context = RequestContext::getMain();

		// Feature: Languages in sidebar
		// ================================
		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				$services->getCentralIdLookupFactory()->getNonLocalLookup(),
				Constants::CONFIG_KEY_LANGUAGE_IN_HEADER,
				Constants::REQUIREMENT_LANGUAGE_IN_HEADER,
				null,
				Constants::CONFIG_LANGUAGE_IN_HEADER_TREATMENT_AB_TEST
			)
		);

		// ---

		// Temporary T286932 - remove after languages A/B test is finished.
		$requirementName = 'T286932';

		// MultiConfig checks each config in turn, allowing us to override the main config for specific keys. In this
		// case, override the "VectorLanguageInHeaderABTest" configuration value so that the following requirement
		// always buckets the user as if the language treatment A/B test were running.
		$config = new MultiConfig( [
			new HashConfig( [
				Constants::CONFIG_LANGUAGE_IN_HEADER_TREATMENT_AB_TEST => true,
			] ),
			$services->getMainConfig(),
		] );

		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$config,
				$context->getUser(),
				$context->getRequest(),
				$services->getCentralIdLookupFactory()->getNonLocalLookup(),
				Constants::CONFIG_KEY_LANGUAGE_IN_HEADER,
				$requirementName,
				/* $overrideName = */ '',
				Constants::CONFIG_LANGUAGE_IN_HEADER_TREATMENT_AB_TEST
			)
		);

		// ---

		$featureManager->registerFeature(
			Constants::FEATURE_LANGUAGE_IN_HEADER,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_LANGUAGE_IN_HEADER,
			]
		);

		// Feature: T293470: Language in main page header
		// ================================
		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				null,
				Constants::CONFIG_LANGUAGE_IN_MAIN_PAGE_HEADER,
				Constants::REQUIREMENT_LANGUAGE_IN_MAIN_PAGE_HEADER
			)
		);

		$featureManager->registerSimpleRequirement(
			Constants::REQUIREMENT_IS_MAIN_PAGE,
			$context->getTitle() ? $context->getTitle()->isMainPage() : false
		);

		$featureManager->registerFeature(
			Constants::FEATURE_LANGUAGE_IN_MAIN_PAGE_HEADER,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_IS_MAIN_PAGE,
				Constants::REQUIREMENT_LANGUAGE_IN_HEADER,
				Constants::REQUIREMENT_LANGUAGE_IN_MAIN_PAGE_HEADER
			]
		);

		// Feature: T295555: Language switch alert in sidebar
		// ================================
		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				null,
				Constants::CONFIG_LANGUAGE_ALERT_IN_SIDEBAR,
				Constants::REQUIREMENT_LANGUAGE_ALERT_IN_SIDEBAR
			)
		);

		$featureManager->registerFeature(
			Constants::FEATURE_LANGUAGE_ALERT_IN_SIDEBAR,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_LANGUAGE_IN_HEADER,
				Constants::REQUIREMENT_LANGUAGE_ALERT_IN_SIDEBAR
			]
		);

		// Feature: Sticky header
		// ================================
		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				null,
				Constants::CONFIG_STICKY_HEADER,
				Constants::REQUIREMENT_STICKY_HEADER
			)
		);

		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				null,
				Constants::CONFIG_STICKY_HEADER_EDIT,
				Constants::REQUIREMENT_STICKY_HEADER_EDIT
			)
		);

		$featureManager->registerFeature(
			Constants::FEATURE_STICKY_HEADER,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_STICKY_HEADER
			]
		);

		$featureManager->registerFeature(
			Constants::FEATURE_STICKY_HEADER_EDIT,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_STICKY_HEADER,
				Constants::REQUIREMENT_STICKY_HEADER_EDIT,
			]
		);

		// T313435 Feature: Table of Contents
		// Temporary - remove after TOC A/B test is finished.
		// ================================
		$featureManager->registerRequirement(
			new TableOfContentsTreatmentRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$services->getCentralIdLookupFactory()->getNonLocalLookup()
			)
		);

		$featureManager->registerFeature(
			Constants::FEATURE_TABLE_OF_CONTENTS,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_TABLE_OF_CONTENTS,
			]
		);

		// Temporary feature: Visual enhancements
		// ================================
		$featureManager->registerRequirement(
			new OverridableConfigRequirement(
				$services->getMainConfig(),
				$context->getUser(),
				$context->getRequest(),
				$services->getCentralIdLookupFactory()->getNonLocalLookup(),
				Constants::CONFIG_KEY_VISUAL_ENHANCEMENTS,
				Constants::REQUIREMENT_VISUAL_ENHANCEMENTS
			)
		);

		$featureManager->registerFeature(
			Constants::FEATURE_VISUAL_ENHANCEMENTS,
			[
				Constants::REQUIREMENT_FULLY_INITIALISED,
				Constants::REQUIREMENT_VISUAL_ENHANCEMENTS,
			]
		);

		return $featureManager;
	}
];
