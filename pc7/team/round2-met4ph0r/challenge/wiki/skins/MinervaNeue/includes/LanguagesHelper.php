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

use MediaWiki\MediaWikiServices;
use OutputPage;
use Title;

/**
 * Helper class to encapsulate logic responsible for checking languages and variants for given title
 * @package MediaWiki\Minerva
 */
class LanguagesHelper {

	/**
	 * @var bool
	 */
	private $hasLanguages;

	/**
	 * @param OutputPage $out Output page to fetch language links
	 */
	public function __construct( OutputPage $out ) {
		$this->hasLanguages = !empty( $out->getLanguageLinks() );
	}

	/**
	 * Whether the Title is also available in other languages or variants
	 * @param Title $title
	 * @return bool
	 */
	public function doesTitleHasLanguagesOrVariants( Title $title ) {
		if ( $this->hasLanguages ) {
			return true;
		}
		$langConv = MediaWikiServices::getInstance()->getLanguageConverterFactory()
			->getLanguageConverter( $title->getPageLanguage() );
		return $langConv->hasVariants();
	}
}
