<?php

namespace MediaWiki\Skins\Vector;

/**
 * @ingroup Skins
 * @package Vector
 * @internal
 */
class SkinVector22 extends SkinVector {
	private const TOC_AB_TEST_NAME = 'skin-vector-toc-experiment';
	private const STICKY_HEADER_ENABLED_CLASS = 'vector-sticky-header-enabled';

	/**
	 * Updates the constructor to conditionally disable table of contents in article
	 * body. Note, the constructor can only check feature flags that do not vary on
	 * whether the user is logged in e.g. features with the 'default' key set.
	 * @inheritDoc
	 */
	public function __construct( array $options ) {
		if ( !$this->isTOCABTestEnabled() ) {
			$options['toc'] = !$this->isTableOfContentsVisibleInSidebar();
		} else {
			$options['styles'][] = 'skins.vector.AB.styles';
		}

		parent::__construct( $options );
	}

	/**
	 * @internal
	 * @return bool
	 */
	public function isTOCABTestEnabled(): bool {
		$experimentConfig = $this->getConfig()->get( Constants::CONFIG_WEB_AB_TEST_ENROLLMENT );

		return $experimentConfig['name'] === self::TOC_AB_TEST_NAME &&
			$experimentConfig['enabled'];
	}

	/**
	 * Check whether the user is bucketed in the treatment group for TOC.
	 *
	 * @return bool
	 */
	public function isUserInTocTreatmentBucket(): bool {
		$featureManager = VectorServices::getFeatureManager();
		return $featureManager->isFeatureEnabled( Constants::FEATURE_TABLE_OF_CONTENTS );
	}

	/**
	 * Determines if the Table of Contents should be visible.
	 * TOC is visible on main namespaces except for the Main Page.
	 *
	 * @internal
	 * @return bool
	 */
	public function isTableOfContentsVisibleInSidebar(): bool {
		$title = $this->getTitle();

		if (
			!$title ||
			$title->isMainPage()
		) {
			return false;
		}

		if ( $this->isTOCABTestEnabled() ) {
			return $title->getArticleID() !== 0;
		}

		return true;
	}

	/**
	 * Annotates table of contents data with Vector-specific information.
	 *
	 * In tableOfContents.js we have tableOfContents::getTableOfContentsSectionsData(),
	 * that yields the same result as this function, please make sure to keep them in sync.
	 *
	 * @param array $tocData
	 * @return array
	 */
	private function getTocData( array $tocData ): array {
		// If the table of contents has no items, we won't output it.
		// empty array is interpreted by Mustache as falsey.
		if ( empty( $tocData ) || empty( $tocData[ 'array-sections' ] ) ) {
			return [];
		}

		// Populate button labels for collapsible TOC sections
		foreach ( $tocData[ 'array-sections' ] as &$section ) {
			if ( $section['is-top-level-section'] && $section['is-parent-section'] ) {
				$section['vector-button-label'] =
					$this->msg( 'vector-toc-toggle-button-label', $section['line'] )->text();
			}
		}

		return array_merge( $tocData, [
			'is-vector-toc-beginning-enabled' => $this->getConfig()->get(
				'VectorTableOfContentsBeginning'
			),
			'vector-is-collapse-sections-enabled' =>
				$tocData[ 'number-section-count'] >= $this->getConfig()->get(
					'VectorTableOfContentsCollapseAtCount'
				)
		] );
	}

	/**
	 * Temporary function while we deprecate SkinVector class.
	 *
	 * @return bool
	 */
	protected function isLegacy(): bool {
		return false;
	}

	/**
	 * Merges the `view-overflow` menu into the `action` menu.
	 * This ensures that the previous state of the menu e.g. emptyPortlet class
	 * is preserved.
	 * @param array $data
	 * @return array
	 */
	private function mergeViewOverflowIntoActions( $data ) {
		$portlets = $data['data-portlets'];
		$actions = $portlets['data-actions'];
		$overflow = $portlets['data-views-overflow'];
		// if the views overflow menu is not empty, then signal that the more menu despite
		// being initially empty now has collapsible items.
		if ( !$overflow['is-empty'] ) {
			$data['data-portlets']['data-actions']['class'] .= ' vector-has-collapsible-items';
		}
		$data['data-portlets']['data-actions']['html-items'] = $overflow['html-items'] . $actions['html-items'];
		return $data;
	}

	/**
	 * @inheritDoc
	 */
	public function getHtmlElementAttributes() {
		$original = parent::getHtmlElementAttributes();

		if ( VectorServices::getFeatureManager()->isFeatureEnabled( Constants::FEATURE_STICKY_HEADER ) ) {
			// T290518: Add scroll padding to root element when the sticky header is
			// enabled. This class needs to be server rendered instead of added from
			// JS in order to correctly handle situations where the sticky header
			// isn't visible yet but we still need scroll padding applied (e.g. when
			// the user navigates to a page with a hash fragment in the URI). For this
			// reason, we can't rely on the `vector-sticky-header-visible` class as it
			// is added too late.
			//
			// Please note that this class applies scroll padding which does not work
			// when applied to the body tag in Chrome, Safari, and Firefox (and
			// possibly others). It must instead be applied to the html tag.
			$original['class'] = implode( ' ', [ $original['class'] ?? '', self::STICKY_HEADER_ENABLED_CLASS ] );
		}

		return $original;
	}

	/**
	 * @return array
	 */
	public function getTemplateData(): array {
		$featureManager = VectorServices::getFeatureManager();
		$parentData = parent::getTemplateData();

		$parentData['data-toc'] = $this->getTocData( $parentData['data-toc'] ?? [] );

		if ( !$this->isTableOfContentsVisibleInSidebar() ) {
			unset( $parentData['data-toc'] );
		}
		$parentData = $this->mergeViewOverflowIntoActions( $parentData );

		return array_merge( $parentData, [
			// Cast empty string to null
			'html-subtitle' => $parentData['html-subtitle'] === '' ? null : $parentData['html-subtitle'],
			'data-vector-sticky-header' => $featureManager->isFeatureEnabled(
				Constants::FEATURE_STICKY_HEADER
			) ? $this->getStickyHeaderData(
				$this->getSearchData(
					$parentData['data-search-box'],
					// Collapse inside search box is disabled.
					false,
					false,
					'vector-sticky-search-form',
					false
				),
				$featureManager->isFeatureEnabled(
					Constants::FEATURE_STICKY_HEADER_EDIT
				)
			) : false,
		] );
	}
}
