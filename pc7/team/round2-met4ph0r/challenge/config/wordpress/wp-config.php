<?php
/**
 * The base configuration for WordPress
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 * @package WordPress
 */

// ** Database settings ** //
define( 'DB_NAME', 'blog_db' );
define( 'DB_USER', 'blog_user' );
define( 'DB_PASSWORD', 'Agent-Ragweed3-Accent' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8' );
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 * @link https://api.wordpress.org/secret-key/1.1/salt/
 */
define( 'AUTH_KEY',         'Womankind-Reshuffle6-Churn' );
define( 'SECURE_AUTH_KEY',  'Implosive1-Neon-Budget' );
define( 'LOGGED_IN_KEY',    'Direction-Tall-Alive3' );
define( 'NONCE_KEY',        'Rift8-Flanked-Purity' );
define( 'AUTH_SALT',        'Expend-Synthetic5-Feminine' );
define( 'SECURE_AUTH_SALT', 'Unbutton-Canopy-Twenty4' );
define( 'LOGGED_IN_SALT',   'Spendable-Overreact-Bulk2' );
define( 'NONCE_SALT',       'Agent-Ragweed3-Accent' );
/**#@-*/

/**
 * WordPress database table prefix.
 */
$table_prefix = 'wp_';

/* --- CTF & Developer Settings --- */

// For developers: WordPress debugging mode.
// Set to false to hide deprecation warnings.
define( 'WP_DEBUG', false );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );

// Intentionally weak settings for the CTF challenge
define( 'DISALLOW_FILE_EDIT', false );
define( 'DISALLOW_FILE_MODS', false );
define( 'ALLOW_UNFILTERED_UPLOADS', true );
define( 'FS_METHOD', 'direct');

// Disable automatic updates
define( 'AUTOMATIC_UPDATER_DISABLED', true );
define( 'WP_AUTO_UPDATE_CORE', false );

define( 'WP_MEMORY_LIMIT', '256M' );

/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
    define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';