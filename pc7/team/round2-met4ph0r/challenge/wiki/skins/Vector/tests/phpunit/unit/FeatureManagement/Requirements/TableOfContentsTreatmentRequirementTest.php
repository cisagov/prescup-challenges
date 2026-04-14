<?php

namespace MediaWiki\Skins\Vector\Tests\Unit\FeatureManagement\Requirements;

use CentralIdLookup;
use HashConfig;
use MediaWiki\Skins\Vector\Constants;
use MediaWiki\Skins\Vector\FeatureManagement\Requirements\TableOfContentsTreatmentRequirement;
use User;

/**
 * @group Vector
 * @group FeatureManagement
 * @coversDefaultClass \MediaWiki\Skins\Vector\FeatureManagement\Requirements\TableOfContentsTreatmentRequirement
 */
class TableOfContentsTreatmentRequirementTest extends \MediaWikiUnitTestCase {

	public function providerTableOfContentsTreatmentRequirement() {
		return [
			[
				// is A-B test enabled
				false,
				// logged-in user with even ID
				10,
				// use central id lookup?
				true,
				false,
				'If nothing enabled, nobody sees new treatment'
			],
			[
				// is A-B test enabled
				true,
				// note 0 = anon user
				0,
				// use central id lookup?
				false,
				false,
				'If test enabled, anon does not see new treatment'
			],
			[
				// is A-B test enabled
				true,
				// logged-in user with even ID
				108,
				// use central id lookup?
				true,
				true,
				'If test enabled, logged-in user with even ID sees new treatment'
			],
			[
				// is A-B test enabled
				true,
				// logged-in user with odd ID
				7,
				// use central id lookup?
				true,
				false,
				'If test enabled, logged-in user with odd ID does not see new treatment'
			],
		];
	}

	/**
	 * @covers ::isMet
	 * @dataProvider providerTableOfContentsTreatmentRequirement
	 * @param bool $abValue
	 * @param int $userId
	 * @param bool $useCentralIdLookup
	 * @param bool $expected
	 * @param string $msg
	 */
	public function testTableOfContentsTreatmentRequirement(
		$abValue, $userId, $useCentralIdLookup, $expected, $msg
	) {
		$config = new HashConfig( [
			Constants::CONFIG_WEB_AB_TEST_ENROLLMENT => [
				'name' => 'skin-vector-toc-experiment',
				'enabled' => $abValue,
				'buckets' => [
					'unsampled' => [
						'samplingRate' => 0,
					],
					'control' => [
						'samplingRate' => 0.5,
					],
					'treatment' => [
						'samplingRate' => 0.5,
					]
				]
			],
		] );

		$user = $this->createMock( User::class );
		$user->method( 'isRegistered' )->willReturn( $userId !== 0 );
		$user->method( 'getID' )->willReturn( $userId );

		$centralIdLookup = $this->createMock( CentralIdLookup::class );
		$centralIdLookup->method( 'centralIdFromLocalUser' )->willReturn( $userId );

		$requirement = new TableOfContentsTreatmentRequirement(
			$config,
			$user,
			$useCentralIdLookup ? $centralIdLookup : null
		);

		$this->assertSame( $expected, $requirement->isMet(), $msg );
	}
}
