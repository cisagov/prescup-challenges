## Install and Configure Wordpress

### Build Ubuntu Server/System

First, you will need to build your own [Ubuntu 20.04](https://releases.ubuntu.com/focal/) or later virtual machine to host the Wordpress site. You can use either the Desktop or Server install image, as this Wordpress instance is very minimal. Ensure that your virtual system has Internet access. You will be required to configure and/or change the IP address when beginning the challenge, which may result in losing Internet access.

See the full [Wordpress Installation and Configuration Guide](https://ubuntu.com/tutorials/install-and-configure-wordpress#1-overview) for more information on the following process.

### Install Dependencies
To install PHP and Apache, use following command:

```bash
sudo apt update
sudo apt install apache2 \
                 ghostscript \
                 libapache2-mod-php \
                 mysql-server \
                 php \
                 php-bcmath \
                 php-curl \
                 php-imagick \
                 php-intl \
                 php-json \
                 php-mbstring \
                 php-mysql \
                 php-xml \
                 php-zip
```

### Install Wordpress
Create the installation directory and download the file from Wo<span>rdPress.o</span>rg:

```bash
sudo mkdir -p /srv/www
sudo chown www-data: /srv/www
curl https://wordpress.org/wordpress-5.9.2.tar.gz | sudo -u www-data tar zx -C /srv/www
```

### Configure Apache for WordPress

Create Apache site for WordPress. Create /etc/apache2/sites-available/wordpress.conf with following lines:

```
<VirtualHost *:80>
    DocumentRoot /srv/www/wordpress
    <Directory /srv/www/wordpress>
        Options FollowSymLinks
        AllowOverride Limit Options FileInfo
        DirectoryIndex index.php
        Require all granted
    </Directory>
    <Directory /srv/www/wordpress/wp-content>
        Options FollowSymLinks
        Require all granted
    </Directory>
</VirtualHost>
```

Enable the site with:
```bash
sudo a2ensite wordpress
```

Enable URL rewriting with:
```bash
sudo a2enmod rewrite
```

Disable the default “It Works” site with:
```bash
sudo a2dissite 000-default
```

Finally, reload apache2 to apply all these changes:
```bash
sudo service apache2 reload
```

### Configure database

Run the following commands, taking note of the customized settings so that your instance of Wordpress will match the imported instance.

```bash
sudo mysql -u root
```

Run the following mysql commands to create the database, user, and allocate permissions. 

```sql
CREATE DATABASE wordpress;

CREATE USER ridley@localhost IDENTIFIED BY 'ridley11';

GRANT SELECT,INSERT,UPDATE,DELETE,CREATE,DROP,ALTER,LOCK TABLES ON wordpress.* TO ridley@localhost;

FLUSH PRIVILEGES;

quit
```

### Install the Wordpress CLI

```bash
curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
```

Make the CLI executable and move to your PATH:
```bash
chmod +x wp-cli.phar
sudo mv wp-cli.phar /usr/local/bin/wp
```

### Import the database
If using a Desktop Ubuntu system, you can directly copy/paste the tspb.sql db file from your local machine, or retrieve it [here](./challenge/wp/tspb.sql)

Otherwise, you will need to enable ssh on the Ubuntu server and scp the files over.

From the directory that contains the tspb.swl file, run the following:

```bash
wp db import tspb.sql --path=/srv/www/wordpress
```

### Import Site Content

If using a Desktop Ubuntu system, you can overwrite the existing /srv/www/wordpress directory with the contents of the [wordpress.zip](./challenge/wp/tspb.sql) provided in the [challenge directory](./challenge)

Otherwise, you will need to enable ssh on the Ubuntu server and scp the file over.

### Set Ridley's Password

```bash
wp user update 1 --user_pass=ridleyGTsamus --path=/srv/www/wordpress
```

### Complete Setup

You may need to restart Apache or reboot the system and should reconfigure your site accessible network interface to use an address of 123.45.100.100/24. This helps ensure that the Wordpress site functions properly.

## Test the Site and Login
Finally, test that the site is accessible over ht<span>tp://123.455.100</span>.100 and the login page is accessible at ht<span>tp://123.45.100.10</span>0/wp-login.php

The initial credentials will be `ridley` | `ridley11`. Due to the time passed since the site was first built, you may be asked to validate the administrator account. You can safely ignore this, or click that the 'ridley' account is still valid.
