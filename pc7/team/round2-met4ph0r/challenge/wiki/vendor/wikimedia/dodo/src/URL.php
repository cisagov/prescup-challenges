<?php

declare( strict_types = 1 );
// @phan-file-suppress PhanTypeExpectedObjectPropAccessButGotNull
// @phan-file-suppress PhanTypeMismatchArgument
// @phan-file-suppress PhanTypeSuspiciousStringExpression
// @phan-file-suppress PhanUndeclaredProperty
// @phan-file-suppress PhanUndeclaredVariable
// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.NotCamelCaps
// phpcs:disable MediaWiki.Commenting.PropertyDocumentation.MissingDocumentationPublic
// phpcs:disable MediaWiki.Commenting.PropertyDocumentation.WrongStyle
// phpcs:disable Squiz.Scope.MethodScope.Missing

namespace Wikimedia\Dodo;

/**
 * URL
 *
 * TODO: This is currently NOT implementing https://url.spec.whatwg.org/#api,
 * but it could, and probably should.
 *
 * TODO: Should probably lean heavily on existing PHP URL-parsing functions?
 * @phan-forbid-undeclared-magic-properties
 */
class URL {

	/**
	 * Return a percentEncoded version of s.
	 * S should be a single-character string
	 * XXX: needs to do utf-8 encoding?
	 *
	 * @param string $s
	 * @return string
	 */
	static function percent_encode( string $s ) {
		return rawurlencode( $s ); /* Yes? */
		//var c = s.charCodeAt(0);
		//if (c < 256) return "%" + c.toString(16);
		//else throw Error("can't percent-encode codepoints > 255 yet");
	}

	/**
	 * @param URL $basepath
	 * @param URL $refpath
	 * @return string|URL
	 */
	static function merge( URL $basepath, URL $refpath ) {
		if ( $base->host !== null && !$base->path ) {
			return "/$refPath";
		}

		$lastslash = strrpos( $basepath->url, '/' );
		if ( $lastslash === false ) {
			return $refpath;
		} else {
			return substr( $basepath->url, 0, $lastslash + 1 ) . $refpath->url;
		}
	}

	/**
	 * @param string|null $path
	 * @return string|null only null if $path was null, otherwise a string
	 */
	static function remove_dot_segments( $path ) {
		if ( !$path ) {
			return $path; // For "" or NULL
		}

		$output = "";
		$match = [];

		while ( strlen( $path ) > 0 ) {
			if ( $path === "." || $path === ".." ) {
				$path = "";
				break;
			}

			$twochars = substr( $path, 0, 2 );
			$threechars = substr( $path, 0, 3 );
			$fourchars = substr( $path, 0, 4 );

			if ( $threechars === "../" ) {
				$path = substr( $path, 3 );
			} elseif ( $twochars === "./" ) {
				$path = substr( $path, 2 );
			} elseif ( $threechars === "/./" ) {
				$path = "/" . substr( $path, 3 );
			} elseif ( $twochars === "/." && strlen( $path ) === 2 ) {
				$path = "/";
			} elseif ( $fourchars === "/../" || ( $threechars === "/.." && strlen( $path ) === 3 ) ) {
				$path = "/" . substr( $path, 4 );

				$output = preg_replace( '/\/?[^\/]*$/', "", $output );
			} else {
				preg_match( '/(\/?([^\/]*))/', $path, $match );
				$segment = $match[0];

				$output .= $segment;

				$path = substr( $path, strlen( $segment ) );
			}
		}

		return $output;
	}

	private const URL_PATTERN = '/^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?$/';
	private const USERINFO_PATTERN = '/^([^@:]*)(:([^@]*))?@/';
	private const PORT_PATTERN = '/:\d+$/';
	private const AUTHORITY_PATTERN = '/^[^:\/?#]+:\/\//';
	private const HIERARCHY_PATTERN = '/^[^:\/?#]+:\//';

	/** @var string|null */
	public $scheme = null;

	/** @var string|null */
	public $host = null; /* contains the hostname followed by ':' and port if specified */

	/** @var string|null */
	public $port = null;

	/** @var string|null */
	public $username = null;

	/** @var string|null */
	public $password = null;

	/** @var string|null */
	public $path = null;

	/** @var string|null */
	public $query = null;

	/** @var string|null */
	public $fragment = null;

	/* TODO: Others from the spec (not covered) */
	public $hostname = null; /* just the hostname (no port) */
	public $pathname = null; /* contains '/' followed by path of URL */
	public $search = null; /* contains '?' followed by parameters of URL */
	public $searchParams = null; /* URLSearchParams allowing access to GET args */
	public $hash = null; /* Containing '#' followed by the fragment identifier */

	/** @var string */
	private $url = '';

	/**
	 * @param string $url
	 */
	public function __construct( string $url = '' ) {
		/*
		 * BEWARE: Can't use trim() since it defines whitespace
		 * differently than HTML
		 *
		 * TODO: Is this still valid in PHP?
		 */
		$this->url = preg_replace( '/^[ \t\n\r\f]+|[ \t\n\r\f]+$/', '', $url );

		/* See http://tools.ietf.org/html/rfc3986#appendix-B */
		/* and https://url.spec.whatwg.org/#parsing */
		$match = [];
		if ( preg_match( self::URL_PATTERN, $this->url, $match ) ) {
			if ( isset( $match[2] ) && $match[2] !== '' ) {
				$this->scheme = $match[2];
			}
			if ( isset( $match[4] ) && $match[4] !== '' ) {
				// parse username/password
				$userinfo = [];
				if ( preg_match( self::USERINFO_PATTERN, $match[4], $userinfo ) ) {
					$this->username = $userinfo[1];
					$this->password = $userinfo[3];

					$match[4] = substr( $match[4], strlen( $userinfo[0] ) );
				}
				if ( preg_match( self::PORT_PATTERN, $match[4] ) ) {
					$pos = strrpos( $match[4], ':' );
					$this->host = substr( $match[4], 0, $pos );
					$this->port = substr( $match[4], $pos + 1 );
				} else {
					$this->host = $match[4];
				}
			}
			if ( isset( $match[5] ) && $match[5] !== '' ) {
				$this->path = $match[5];
			}
			if ( isset( $match[6] ) && $match[6] !== '' ) {
				$this->query = $match[7];
			}
			if ( isset( $match[8] ) && $match[8] !== '' ) {
				$this->fragment = $match[9];
			}
		}
	}

	/**
	 * XXX: not sure if this is the precise definition of absolute
	 *
	 * @return bool
	 */
	public function isAbsolute() {
		return (bool)$this->scheme;
	}

	/** @return bool */
	public function isAuthorityBased() {
		return (bool)preg_match( self::AUTHORITY_PATTERN, $this->url );
	}

	/** @return bool */
	public function isHierarchical() {
		return (bool)preg_match( self::HIERARCHY_PATTERN, $this->url );
	}

	/** @return string */
	public function toString() {
		$s = "";

		if ( $this->scheme !== null ) {
			$s .= $this->scheme . ':';
		}
		if ( $this->isAbsolute() ) {
			$s .= '//';
			if ( $this->username || $this->password ) {
				/* BEWARE: tested NULL and '' */
				if ( $this->username !== null ) {
					$s .= $this->username;
				}
				if ( $this->password ) {
					/* BEWARE: tested NULL and '' */
					$s .= ':' . $this->pass;
				}
				$s .= '@';
			}
			if ( $this->host !== null ) {
				$s .= $this->host;
			}
		}
		if ( $this->port !== null ) {
			$s .= ':' . $this->port;
		}
		if ( $this->path !== null ) {
			$s .= $this->path;
		}
		if ( $this->query !== null ) {
			$s .= '?' . $this->query;
		}
		if ( $this->fragment !== null ) {
			$s .= '#' . $this->fragment;
		}
		return $s;
	}

	/**
	 * @see http://tools.ietf.org/html/rfc3986#section-5.2
	 * @see https://url.spec.whatwg.org/#constructors
	 *
	 * @param string $relative
	 * @return string
	 */
	public function resolve( $relative ) {
		// The base url we're resolving against
		$base = $this;

		// The relative reference url to resolve
		$relativeURL = new URL( $relative );

		// The absolute target url we will return
		$targetURL = new URL();

		if ( $relativeURL->scheme !== null ) {
			$targetURL->scheme = $relativeURL->scheme;
			$targetURL->username = $relativeURL->username;
			$targetURL->password = $relativeURL->password;
			$targetURL->host = $relativeURL->host;
			$targetURL->port = $relativeURL->port;
			$targetURL->path = self::remove_dot_segments( $relativeURL->path );
			$targetURL->query = $relativeURL->query;
		} else {
			$targetURL->scheme = $base->scheme;

			if ( $relativeURL->host !== null ) {
				$targetURL->username = $relativeURL->username;
				$targetURL->password = $relativeURL->password;
				$targetURL->host = $relativeURL->host;
				$targetURL->port = $relativeURL->port;
				$targetURL->path = self::remove_dot_segments( $relativeURL->path );
				$targetURL->query = $relativeURL->query;
			} else {
				$targetURL->username = $base->username;
				$targetURL->password = $base->password;
				$targetURL->host = $base->host;
				$targetURL->port = $base->port;

				if ( !$relativeURL->path ) {
					/* non-NULL and non-empty */
					$targetURL->path = $base->path;
					$targetURL->query = $relativeURL->query ?? $base->query;
				} else {
					if ( $relativeURL->path[0] === '/' ) {
						$targetURL->path = self::remove_dot_segments( $relativeURL->path );
					} else {
						$targetURL->path = self::merge( $base->path, $relativeURL->path );
						$targetURL->path = self::remove_dot_segments( $targetURL->path );
					}
					$targetURL->query = $relativeURL->query;
				}
			}
		}
		$targetURL->fragment = $relativeURL->fragment;

		return $targetURL->toString();
	}
}

/* TODO TODO TODO */

//abstract class URLUtils
//{
//abstract function href(string $val=NULL);

//private function _url()
//{
/*
 * XXX: this should do the "Reinitialize url" steps,
 * and "null" should be a valid return value.
 */
//return new URL($this->href());
//}

//public function protocol(string $val=NULL)
//{
//if ($val == NULL) {
//[> GET <]
//$url = $this->_url();
//if ($url && $url->scheme) {
//return $url->scheme . ":";
//} else {
//return ":";
//}
//} else {
//[> SET <]
//$out = $this->href();
//$url = new URL($out);
//if ($url->isAbsolute()) {
//$val = $val

//}
//}
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute()) {
//v = v.replace(/:+$/, "");
//v = v.replace(/[^-+\.a-zA-Z0-9]/g, URL.percentEncode);
//if (v.length > 0) {
//url.scheme = v;
//output = url.toString();
//}
//}
//this.href = output;
//},
//},

//host: {
//get: function() {
//var url = this._url;
//if (url.isAbsolute() && url.isAuthorityBased())
//return url.host + (url.port ? (":" + url.port) : "");
//else
//return "";
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute() && url.isAuthorityBased()) {
//v = v.replace(/[^-+\._~!$&'()*,;:=a-zA-Z0-9]/g, URL.percentEncode);
//if (v.length > 0) {
//url.host = v;
//delete url.port;
//output = url.toString();
//}
//}
//this.href = output;
//},
//},

//hostname: {
//get: function() {
//var url = this._url;
//if (url.isAbsolute() && url.isAuthorityBased())
//return url.host;
//else
//return "";
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute() && url.isAuthorityBased()) {
//v = v.replace(/^\/+/, "");
//v = v.replace(/[^-+\._~!$&'()*,;:=a-zA-Z0-9]/g, URL.percentEncode);
//if (v.length > 0) {
//url.host = v;
//output = url.toString();
//}
//}
//this.href = output;
//},
//},

//port: {
//get: function() {
//var url = this._url;
//if (url.isAbsolute() && url.isAuthorityBased() && url.port!==undefined)
//return url.port;
//else
//return "";
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute() && url.isAuthorityBased()) {
//v = '' + v;
//v = v.replace(/[^0-9].*$/, "");
//v = v.replace(/^0+/, "");
//if (v.length === 0) v = "0";
//if (parseInt(v, 10) <= 65535) {
//url.port = v;
//output = url.toString();
//}
//}
//this.href = output;
//},
//},

//pathname: {
//get: function() {
//var url = this._url;
//if (url.isAbsolute() && url.isHierarchical())
//return url.path;
//else
//return "";
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute() && url.isHierarchical()) {
//if (v.charAt(0) !== "/")
//v = "/" + v;
//v = v.replace(/[^-+\._~!$&'()*,;:=@\/a-zA-Z0-9]/g, URL.percentEncode);
//url.path = v;
//output = url.toString();
//}
//this.href = output;
//},
//},

//search: {
//get: function() {
//var url = this._url;
//if (url.isAbsolute() && url.isHierarchical() && url.query!==undefined)
//return "?" + url.query;
//else
//return "";
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute() && url.isHierarchical()) {
//if (v.charAt(0) === "?") v = v.substring(1);
//v = v.replace(/[^-+\._~!$&'()*,;:=@\/?a-zA-Z0-9]/g, URL.percentEncode);
//url.query = v;
//output = url.toString();
//}
//this.href = output;
//},
//},

//hash: {
//get: function() {
//var url = this._url;
//if (url == null || url.fragment == null || url.fragment === '') {
//return "";
//} else {
//return "#" + url.fragment;
//}
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);

//if (v.charAt(0) === "#") v = v.substring(1);
//v = v.replace(/[^-+\._~!$&'()*,;:=@\/?a-zA-Z0-9]/g, URL.percentEncode);
//url.fragment = v;
//output = url.toString();

//this.href = output;
//},
//},

//username: {
//get: function() {
//var url = this._url;
//return url.username || '';
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute()) {
//v = v.replace(/[\x00-\x1F\x7F-\uFFFF "#<>?`\/@\\:]/g, URL.percentEncode);
//url.username = v;
//output = url.toString();
//}
//this.href = output;
//},
//},

//password: {
//get: function() {
//var url = this._url;
//return url.password || '';
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//if (url.isAbsolute()) {
//if (v==='') {
//url.password = null;
//} else {
//v = v.replace(/[\x00-\x1F\x7F-\uFFFF "#<>?`\/@\\]/g, URL.percentEncode);
//url.password = v;
//}
//output = url.toString();
//}
//this.href = output;
//},
//},

//origin: { get: function() {
//var url = this._url;
//if (url == null) { return ''; }
//var originForPort = function(defaultPort) {
//var origin = [url.scheme, url.host, +url.port || defaultPort];
//// XXX should be "unicode serialization"
//return origin[0] + '://' + origin[1] +
//(origin[2] === defaultPort ? '' : (':' + origin[2]));
//};
//switch (url.scheme) {
//case 'ftp':
//return originForPort(21);
//case 'gopher':
//return originForPort(70);
//case 'http':
//case 'ws':
//return originForPort(80);
//case 'https':
//case 'wss':
//return originForPort(443);
//default:
//// this is what chrome does
//return url.scheme + '://';
//}
//} },

//[>
//searchParams: {
//get: function() {
//var url = this._url;
//// XXX
//},
//set: function(v) {
//var output = this.href;
//var url = new URL(output);
//// XXX
//this.href = output;
//},
//},
//*/
//});
