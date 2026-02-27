<?php

namespace MediaWiki\Minerva;

use ILanguageConverter;
use Language;
use MediaWiki\Languages\LanguageConverterFactory;
use MediaWikiIntegrationTestCase;
use OutputPage;
use PHPUnit\Framework\MockObject\Invocation;
use Title;

/**
 * @package Tests\MediaWiki\Minerva
 * @group MinervaNeue
 * @coversDefaultClass \MediaWiki\Minerva\LanguagesHelper
 */
class LanguagesHelperTest extends MediaWikiIntegrationTestCase {

	/**
	 * Build test Output object
	 * @param array $langLinks
	 * @return OutputPage
	 */
	private function getOutput( array $langLinks ) {
		$out = $this->createMock( OutputPage::class );
		$out->expects( $this->once() )
			->method( 'getLanguageLinks' )
			->willReturn( $langLinks );

		return $out;
	}

	/**
	 * Build test Title object
	 * @param bool $hasVariants
	 * @param Invocation|null $matcher
	 * @return Title
	 */
	private function getTitle( $hasVariants, Invocation $matcher = null ) {
		$languageMock = $this->createMock( Language::class );
		$langConv = $this->createMock( ILanguageConverter::class );
		$langConv->expects( $matcher ?? $this->any() )->method( 'hasVariants' )->willReturn( $hasVariants );
		$langConvFactory = $this->createMock( LanguageConverterFactory::class );
		$langConvFactory->method( 'getLanguageConverter' )->with( $languageMock )->willReturn( $langConv );
		$this->setService( 'LanguageConverterFactory', $langConvFactory );

		$title = $this->createMock( Title::class );
		$title->expects( $matcher ?? $this->any() )
			->method( 'getPageLanguage' )
			->willReturn( $languageMock );

		return $title;
	}

	/**
	 * @covers ::__construct
	 * @covers ::doesTitleHasLanguagesOrVariants
	 */
	public function testReturnsWhenOutputPageHasLangLinks() {
		$helper = new LanguagesHelper( $this->getOutput( [ 'pl:StronaTestowa', 'en:TestPage' ] ) );

		$this->assertTrue( $helper->doesTitleHasLanguagesOrVariants( $this->getTitle( false ) ) );
		$this->assertTrue( $helper->doesTitleHasLanguagesOrVariants( $this->getTitle( true ) ) );
	}

	/**
	 * @covers ::__construct
	 * @covers ::doesTitleHasLanguagesOrVariants
	 */
	public function testReturnsWhenOutputDoesNotHaveLangLinks() {
		$helper = new LanguagesHelper( $this->getOutput( [] ) );

		$this->assertFalse( $helper->doesTitleHasLanguagesOrVariants(
			$this->getTitle( false ), $this->once() ) );
		$this->assertTrue( $helper->doesTitleHasLanguagesOrVariants(
			$this->getTitle( true ), $this->once() ) );
	}
}
