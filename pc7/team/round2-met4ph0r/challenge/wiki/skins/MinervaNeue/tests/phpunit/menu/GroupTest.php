<?php

namespace MediaWiki\Minerva\Menu;

use DomainException;
use MediaWiki\Minerva\Menu\Entries\IMenuEntry;
use MediaWiki\Minerva\Menu\Entries\SingleMenuEntry;
use MediaWikiIntegrationTestCase;

/**
 * @group MinervaNeue
 * @coversDefaultClass \MediaWiki\Minerva\Menu\Group
 */
class GroupTest extends MediaWikiIntegrationTestCase {
	/** @var string[] */
	private $homeComponent = [
		'text' => 'Home',
		'href' => '/Main_page',
		'class' => 'mw-ui-icon mw-ui-icon-before mw-ui-icon-home',
		'data-event-name' => 'menu.home',
		'icon' => null
	];

	/** @var string[] */
	private $nearbyComponent = [
		'text' => 'Nearby',
		'href' => '/wiki/Special:Nearby',
		'class' => 'mw-ui-icon mw-ui-icon-before mw-ui-icon-nearby',
		'icon' => null
	];

	/**
	 * @covers ::getEntries
	 * @covers ::hasEntries
	 */
	public function testItShouldntHaveEntriesByDefault() {
		$menu = new Group( 'p-test' );

		$this->assertEmpty( $menu->getEntries() );
		$this->assertFalse( $menu->hasEntries() );
	}

	/**
	 * @covers ::insertEntry
	 * @covers ::search
	 * @covers ::getEntries
	 * @covers ::hasEntries
	 */
	public function testInsertingAnEntry() {
		$menu = new Group( 'p-test' );
		$entry = SingleMenuEntry::create(
			'home',
			$this->homeComponent['text'],
			$this->homeComponent['href'],
			$this->homeComponent['class'],
			$this->homeComponent['icon'],
			true
		);
		$menu->insertEntry( $entry );

		$expectedEntries = [
			[
				'name' => 'home',
				'components' => [
					[
						'text' => $this->homeComponent['text'],
						'href' => $this->homeComponent['href'],
						'class' => 'mw-ui-icon mw-ui-icon-before mw-ui-icon-home menu__item--home',
						'icon' => 'minerva-home',
						'data-event-name' => 'menu.home'
					]
				 ],
			],
		];

		$this->assertEquals( $expectedEntries, $menu->getEntries() );
		$this->assertTrue( $menu->hasEntries() );
	}

	/**
	 * @covers ::insertEntry
	 */
	public function testInsertingAnEntryWithAnExistingName() {
		$menu = new Group( 'p-test' );
		$entryHome = SingleMenuEntry::create(
			'home',
			$this->homeComponent['text'],
			$this->homeComponent['href'],
			$this->homeComponent['class']
		);
		$menu->insertEntry( $entryHome );
		$this->expectException( DomainException::class );
		$this->expectExceptionMessage( 'The "home" entry already exists.' );
		$menu->insertEntry( $entryHome );
	}

	/**
	 * @covers ::insertEntry
	 * @covers ::getEntries
	 */
	public function testInsertingAJavascriptOnlyEntry() {
		$menu = new Group( 'p-test' );
		$entryHome = SingleMenuEntry::create(
			'nearby',
			$this->nearbyComponent['text'],
			$this->nearbyComponent['href'],
			$this->nearbyComponent['class']
		);
		$entryHome->setJSOnly();
		$menu->insertEntry( $entryHome );

		$expectedEntries = [
			[
				'name' => 'nearby',
				'components' => [
					[
						'text' => $this->nearbyComponent['text'],
						'href' => $this->nearbyComponent['href'],
						'class' => 'mw-ui-icon mw-ui-icon-before mw-ui-icon-nearby menu__item--nearby',
						'icon' => 'minerva-nearby'
					]
				],
				'class' => 'jsonly'
			],
		];

		$this->assertEquals( $expectedEntries, $menu->getEntries() );
	}

	/**
	 * @covers ::getEntryByName
	 * @covers ::search
	 */
	public function testGetEntryByName() {
		$menu = new Group( 'p-test' );
		$entryHome = SingleMenuEntry::create(
			'home',
			$this->homeComponent['text'],
			$this->homeComponent['href'],
			$this->homeComponent['class']
		);
		$menu->insertEntry( $entryHome );
		$this->assertInstanceOf( IMenuEntry::class, $menu->getEntryByName( 'home' ) );
	}

	/**
	 * @covers ::getEntryByName
	 * @covers ::search
	 */
	public function testGetEntryByNameException() {
		$menu = new Group( 'p-test' );
		$this->expectException( DomainException::class );
		$menu->getEntryByName( 'home' );
	}

}
