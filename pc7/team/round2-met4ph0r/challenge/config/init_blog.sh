#!/bin/bash

# Wait for MySQL to be ready
sleep 5

# Create WordPress database and user
mysql -u root << EOF
CREATE DATABASE IF NOT EXISTS blog_db;
CREATE USER IF NOT EXISTS 'blog_user'@'localhost' IDENTIFIED BY 'Agent-Ragweed3-Accent';
GRANT ALL PRIVILEGES ON blog_db.* TO 'blog_user'@'localhost';
UPDATE mysql.user SET plugin = 'mysql_native_password' WHERE User = 'blog_user' AND Host = 'localhost';
FLUSH PRIVILEGES;
EOF

# Apply DB schema, injecting admin password from env var `USER_PASSWORD`
echo "Applying blog schema..."
# Locate schema and read password from env var `USER_PASSWORD`
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="$SCRIPT_DIR/blog_schema.sql"
BLOG_PWD=$(printenv 'USER_PASSWORD')
# Escape single quotes for safe SQL literal
ESCAPED_BLOG_PWD=$(printf "%s" "$BLOG_PWD" | sed "s/'/'\\''/g")
( printf "SET @BLOG_PWD='%s';\nUSE blog_db;\n" "$ESCAPED_BLOG_PWD"; cat "$SCHEMA_FILE" ) | mysql -u root
echo "Schema applied."

# Configure WordPress
echo "Configuring WordPress..."
BLOG_PWD=$(printenv 'USER_PASSWORD')

sudo -u www-data wp core install --path=/var/www/blog \
    --url=http://m3t4ph0r:8081 \
    --title="PeanutCo Internal Blog" \
    --admin_user=scott \
    --admin_password="$BLOG_PWD" \
    --admin_email=admin@blog.local \
    --skip-email

# Activate the wp-file-manager plugin
echo "Activating wp-file-manager plugin..."
sudo -u www-data wp plugin activate wp-file-manager --path=/var/www/blog

# Create initial blog post
echo "Creating welcome post..."
sudo -u www-data wp post create --path=/var/www/blog \
    --post_type=post \
    --post_title="Welcome to the Corporate Blog" \
    --post_content="There is totally nothing insecure here, I promise :P" \
    --post_status=publish \
    --post_author=1

# Ensure proper permissions
chown -R www-data:www-data /var/www/blog
find /var/www/blog -type d -exec chmod 755 {} \;
find /var/www/blog -type f -exec chmod 644 {} \;
chmod 777 /var/www/blog/wp-content/uploads