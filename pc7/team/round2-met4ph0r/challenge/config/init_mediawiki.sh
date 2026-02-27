#!/bin/bash

# MediaWiki CTF Challenge Initialization Script
# This script sets up MediaWiki with the challenge scenario

## AC Added
USERPASSWORD=$USER_PASSWORD


echo "Starting MediaWiki CTF Challenge initialization..."

# Check if MediaWiki is already installed
if ! mysql -u wiki_user -pEaster-Unmixable2-Previous wiki_db -e "SHOW TABLES LIKE 'user';" | grep -q user; then
    echo "Installing MediaWiki tables..."
    cd /ctf/wiki
    
    # Remove LocalSettings.php temporarily during installation
    mv LocalSettings.php LocalSettings.php.backup 2>/dev/null || true
    
    # Install MediaWiki
    php maintenance/install.php \
        --dbtype=mysql \
        --dbserver=localhost \
        --dbname=wiki_db \
        --dbuser=wiki_user \
        --dbpass=Easter-Unmixable2-Previous \
        --server="http://localhost" \
        --scriptpath="" \
        --lang=en \
        --pass=admin123456 \
        --with-extensions \
        "CTF Internal Wiki" \
        "admin"
    
    # Restore our custom LocalSettings.php
    mv LocalSettings.php.backup LocalSettings.php 2>/dev/null || true
    
    echo "MediaWiki installation completed!"
else
    echo "MediaWiki already installed, skipping installation..."
fi

# Create MediaWiki content with PeanutCo company pages
echo "Creating PeanutCo company wiki pages..."

cd /ctf/wiki

# Update MediaWiki database schema if needed
php maintenance/update.php --quick

# Create additional user with maintenance script (skip if exists)
if ! mysql -u wiki_user -pEaster-Unmixable2-Previous wiki_db -e "SELECT user_name FROM user WHERE user_name='Wikiuser';" | grep -q Wikiuser; then
    echo "Creating additional user..."
    php maintenance/createAndPromote.php --force --bureaucrat --sysop wikiuser wikiuser123 || echo "User creation failed, continuing..."
fi

# Copy and register the JAR file in MediaWiki
echo "Copying and registering scott_patch.jar in MediaWiki..."
cp /ctf/scott_patch.jar /ctf/wiki/images/
chown www-data:www-data /ctf/wiki/images/scott_patch.jar

# Register the file in MediaWiki's database
cd /ctf/wiki
php maintenance/importImages.php --user=admin --comment="Security update file" /ctf/wiki/images/ scott_patch.jar

# Create a temporary page with the JAR file, then delete it (keeping in history)
echo "Creating temporary software update page with JAR file..."
cd /ctf/wiki

# Create the page with JAR file
php maintenance/edit.php -u admin -s 'Critical security update available' 'Software_Security_Update' << 'JARPAGE'
= Critical Security Update Required =

**URGENT: All employees must install this security patch immediately**

== Security Update Package v3.2.1 ==
This update addresses critical vulnerabilities in our internal systems discovered by our security team.

**Download:** [[File:scott_patch.jar|Security Update Installer]]

== Installation Instructions ==
1. Download the JAR file above
2. Run with administrator privileges: `java -jar scott_patch.jar`
3. Follow the on-screen prompts
4. Restart your workstation after installation

== Technical Details ==
* Release Date: Current
* Priority: Critical
* Affects: All company workstations
* Contact: IT Security Team for installation support

**Note:** This update must be installed within 48 hours per company security policy.

== Support ==
For installation issues, contact:
* IT Help Desk: ext. 2847
* Security Team: security@peanutco.local
* Emergency IT Support: 555-247-TECH

[[Category:Security]] [[Category:Updates]]
JARPAGE

# Now delete the page but keep it in revision history

echo "Removing security update page \(policy compliance\)..."
php maintenance/deleteBatch.php << 'DELETELIST'
Software_Security_Update
DELETELIST

echo "Security update page removed per security policy \(available in revision history\)"

# Create PeanutCo wiki pages using separate script
echo "Creating PeanutCo company wiki pages..."
chmod +x /ctf/config/init_pages.sh
/ctf/config/init_pages.sh

echo "MediaWiki Challenge initialization complete!"
echo "Services:"
echo "  - MediaWiki: http://m3t4ph0r:80"
echo ""
echo "Security Features:"
echo "  - JAR file with Scott's debugging system uploaded and archived"
echo "  - Security update page deleted (available in revision history)"
echo "  - JAR accessible via: /images/scott_patch.jar"
echo "  - Password hint: $USERPASSWORD"
