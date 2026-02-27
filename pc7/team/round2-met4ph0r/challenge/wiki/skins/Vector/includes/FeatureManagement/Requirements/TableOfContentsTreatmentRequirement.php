<?php

namespace MediaWiki\Skins\Vector\FeatureManagement\Requirements;

use CentralIdLookup;
use Config;
use MediaWiki\Skins\Vector\Constants;
use MediaWiki\Skins\Vector\FeatureManagement\Requirement;
use RuntimeException;
use User;

/**
 * Checks whether or not sticky Table of Contents should be shown.
 *
 * @unstable
 *
 * @package Vector\FeatureManagement\Requirements
 * @internal
 */
final class TableOfContentsTreatmentRequirement implements Requirement {
	/**
	 * @var Config
	 */
	private $config;

	/**
	 * @var User
	 */
	private $user;

	/**
	 * @var CentralIdLookup
	 */
	private $centralIdLookup;

	/**
	 * @param Config $config
	 * @param User $user
	 * @param CentralIdLookup|null $centralIdLookup
	 */
	public function __construct(
		Config $config,
		User $user,
		?CentralIdLookup $centralIdLookup
	) {
		$this->config = $config;
		$this->user = $user;
		$this->centralIdLookup = $centralIdLookup;
	}

	/**
	 * @inheritDoc
	 */
	public function getName(): string {
		return Constants::REQUIREMENT_TABLE_OF_CONTENTS;
	}

	/**
	 * If A/B test is enabled check whether the user is logged in and bucketed.
	 *
	 * @inheritDoc
	 * @throws \ConfigException
	 */
	public function isMet(): bool {
		$currentAbTest = $this->config->get( Constants::CONFIG_WEB_AB_TEST_ENROLLMENT );
		$isTOCExperiment = $currentAbTest['name'] === 'skin-vector-toc-experiment';
		if ( $isTOCExperiment && $currentAbTest['enabled'] && $this->user->isRegistered() ) {
			$id = null;
			$buckets = $currentAbTest['buckets'] ?? [];
			$control = $buckets['control']['samplingRate'] ?? -1;
			$unsampled = $buckets['unsampled']['samplingRate'] ?? -1;
			$numBuckets = count( array_keys( $buckets ) );
			if ( $unsampled !== 0 || $control !== 0.5 || $numBuckets !== 3 ) {
				throw new RuntimeException( 'TableOfContents A/B test only supports 3 buckets with 0 unsampled.' );
			}

			if ( $this->centralIdLookup ) {
				$id = $this->centralIdLookup->centralIdFromLocalUser( $this->user );
			}

			// $id will be 0 if the central ID lookup failed.
			if ( !$id ) {
				$id = $this->user->getId();
			}

			// This assume 100% sampling of logged-in users with roughly half
			// in control or treatment buckets based on even or odd user ids.
			// This does not cover unsampled users nor does it consider the
			// sampling rates of any given bucket passed in via config.
			return $id % 2 === 0;
		}
		return false;
	}
}
