<?php

namespace MediaWiki\Minerva;

use MediaWiki\Minerva\Skins\SkinUserPageHelper;
use MediaWikiIntegrationTestCase;
use Title;

/**
 * @group MinervaNeue
 * @coversDefaultClass \MediaWiki\Minerva\Skins\SkinUserPageHelper
 */
class SkinUserPageHelperTest extends MediaWikiIntegrationTestCase {

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 * @covers ::__construct
	 */
	public function testTitleNotInUserNamespace() {
		$title = Title::makeTitle( NS_MAIN, 'Test_Page' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertFalse( $helper->isUserPage() );
	}

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 * @covers ::__construct
	 */
	public function testTitleIsNull() {
		$title = null;

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertNull( $helper->getPageUser() );
		$this->assertFalse( $helper->isUserPage() );
	}

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 */
	public function testTitleisASubpage() {
		$title = Title::makeTitle( NS_USER, 'TestUser/subpage' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertFalse( $helper->isUserPage() );
	}

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 * @covers ::buildPageUserObject
	 */
	public function testTitleisAnIP() {
		$title = Title::makeTitle( NS_USER, '127.0.0.1' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertTrue( $helper->isUserPage() );
	}

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 * @covers ::buildPageUserObject
	 */
	public function testTitleIsIPRange() {
		$title = Title::makeTitle( NS_USER, '127.0.0.1/24' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertFalse( $helper->isUserPage() );
	}

	/**
	 * @covers ::isUserPage
	 * @covers ::fetchData
	 * @covers ::buildPageUserObject
	 */
	public function testTitleIsFakeUserPage() {
		$title = Title::makeTitle( NS_USER, 'Fake_user' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertFalse( $helper->isUserPage() );
	}

	/**
	 * @covers ::fetchData
	 */
	public function testTitleProcessingIsCached() {
		$titleMock = $this->getMockBuilder( Title::class )
			->disableOriginalConstructor()
			->getMock();
		$titleMock->expects( $this->once() )
			->method( 'inNamespace' )
			->with( NS_USER )
			->willReturn( true );

		$titleMock->expects( $this->once() )
			->method( 'isSubpage' )
			->willReturn( false );

		$titleMock->expects( $this->once() )
			->method( 'getText' )
			->willReturn( 'Test' );

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $titleMock );
		$helper->isUserPage();
		$helper->isUserPage();
		$helper->getPageUser();
		$helper->getPageUser();
	}

	/**
	 * @covers ::fetchData
	 * @covers ::getPageUser
	 * @covers ::isUserPage
	 */
	public function testGetPageUserWhenOnUserPage() {
		$testUser = $this->getTestUser()->getUser();
		$title = $testUser->getUserPage();

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $title );
		$this->assertTrue( $helper->isUserPage() );
		$this->assertEquals( $testUser->getId(), $helper->getPageUser()->getId() );
	}

	/**
	 * @covers ::fetchData
	 * @covers ::getPageUser
	 * @covers ::isUserPage
	 */
	public function testGetPageUserWhenOnUserPageReturnsCorrectUser() {
		$testUser = $this->getTestUser()->getUser();
		$testUserTitle = $testUser->getUserPage();

		$secondTestUser = $this->getTestSysop()->getUser();
		$secondTestUserTitle = $secondTestUser->getUserPage();

		$helper = new SkinUserPageHelper( $this->getServiceContainer()->getUserNameUtils(), $secondTestUserTitle );
		$this->assertTrue( $helper->isUserPage() );
		$this->assertNotEquals( $testUser->getId(), $helper->getPageUser()->getId() );
		$this->assertNotEquals( $helper->getPageUser()->getUserPage(), $testUserTitle );
	}

}
