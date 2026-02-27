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

namespace MediaWiki\Minerva\Skins;

use IContextSource;
use MediaWiki\User\UserNameUtils;
use Title;
use User;

class SkinUserPageHelper {
	/**
	 * @var UserNameUtils
	 */
	private $userNameUtils;

	/**
	 * @var Title|null
	 */
	private $title;

	/**
	 * @var bool
	 */
	private $fetchedData = false;

	/**
	 * @var User
	 */
	private $pageUser;

	/**
	 * @var IContextSource|null
	 */
	private $context;

	/**
	 * @param UserNameUtils $userNameUtils
	 * @param Title|null $title
	 * @param IContextSource|null $context
	 */
	public function __construct( UserNameUtils $userNameUtils, Title $title = null, IContextSource $context = null ) {
		$this->userNameUtils = $userNameUtils;
		$this->title = $title;
		$this->context = $context;
	}

	/**
	 * Fetch user data and store locally for performance improvement
	 * @return User|null
	 */
	private function fetchData() {
		if ( $this->fetchedData === false ) {
			if ( $this->title && $this->title->inNamespace( NS_USER ) && !$this->title->isSubpage()
			) {
				$this->pageUser = $this->buildPageUserObject( $this->title );
			}
			$this->fetchedData = true;
		}
		return $this->pageUser;
	}

	/**
	 * Return new User object based on username or IP address.
	 * @param Title $title
	 * @return User|null
	 */
	private function buildPageUserObject( Title $title ) {
		$titleText = $title->getText();

		if ( $this->userNameUtils->isIP( $titleText ) ) {
			return User::newFromAnyId( null, $titleText, null );
		}

		$pageUserId = User::idFromName( $titleText );
		if ( $pageUserId ) {
			return User::newFromId( $pageUserId );
		}

		return null;
	}

	/**
	 * @return User|null
	 */
	public function getPageUser() {
		return $this->fetchData();
	}

	/**
	 * @return bool
	 */
	public function isUserPage() {
		return $this->fetchData() !== null;
	}

	/**
	 * @return bool
	 */
	public function isUserPageAccessibleToCurrentUser() {
		$pageUser = $this->fetchData();
		$isHidden = $pageUser && $pageUser->isHidden();
		$canViewHidden = $this->context && $this->context->getAuthority()->isAllowed( 'hideuser' );
		return !$isHidden || $canViewHidden;
	}
}
