<?php

namespace MediaWiki\Skins\Vector\ResourceLoader;

use MediaWiki\ResourceLoader as RL;
use MediaWiki\Skins\Vector\Constants;

class VectorResourceLoaderUserModule extends RL\UserModule {
	/**
	 * @inheritDoc
	 */
	protected function getPages( RL\Context $context ) {
		$skin = $context->getSkin();
		$config = $this->getConfig();
		$user = $context->getUserObj();
		$pages = [];
		if ( $config->get( 'AllowUserCss' ) && !$user->isAnon() && ( $skin === Constants::SKIN_NAME_MODERN ) ) {
			$userPage = $user->getUserPage()->getPrefixedDBkey();
			$pages["$userPage/vector.js"] = [ 'type' => 'script' ];
		}
		return $pages;
	}
}
