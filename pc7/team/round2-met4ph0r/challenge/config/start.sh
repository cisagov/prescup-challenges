#!/bin/bash

# MariaDB is baked into the image; ensure runtime dirs exist
mkdir -p /var/run/mysqld && chown mysql:mysql /var/run/mysqld
# Compile Java JAR with dynamic password injection
echo "Compiling scott_patch.jar with dynamic password..."
cd /ctf/jar
# Substitute the placeholder with the actual password from env var
sed "s/__USER_PASSWORD_PLACEHOLDER__/${USER_PASSWORD}/g" VulnJar.java > VulnJar_temp.java
mv VulnJar_temp.java VulnJar.java
# Compile the Java file
javac VulnJar.java
if [ $? -ne 0 ]; then
    echo "ERROR: javac compilation failed!"
    exit 1
fi
# Create the JAR with manifest
jar cvfm scott_patch.jar manifest.txt VulnJar.class
# Overwrite the build-time placeholder JAR so init_mediawiki.sh picks up the real one
cp /ctf/jar/scott_patch.jar /ctf/scott_patch.jar
echo "JAR compiled and deployed with injected password"

# Compile vuln_binary with dynamic password injection
echo "Compiling vuln_binary with dynamic password..."
cd /ctf/privesc
sed "s/__USER_PASSWORD_PLACEHOLDER__/${USER_PASSWORD}/g" vuln_binary.c > vuln_binary_temp.c
gcc -o vuln_binary vuln_binary_temp.c -fno-stack-protector -z execstack -no-pie
if [ $? -ne 0 ]; then
    echo "ERROR: vuln_binary compilation failed!"
    exit 1
fi
strip --strip-all vuln_binary
cp vuln_binary /usr/local/bin/vuln_binary
chown root:root /usr/local/bin/vuln_binary
chmod 4511 /usr/local/bin/vuln_binary
# Clean up source so competitors can't just read it
rm -f vuln_binary_temp.c vuln_binary
echo "vuln_binary compiled and deployed with injected password"

# log directory
mkdir -p /var/log/supervisor

# Add PID limits to respect infra constraints
mkdir -p /var/log/supervisor /var/log/mysql /var/run/mysqld
chown mysql:mysql /var/log/mysql /var/run/mysqld

# Aight we taking the nuclear option here, and rewriting the mysql config to use minimal resources
echo "Enforcing PID Limits on MariaDB configuration..."
cat >/etc/mysql/mariadb.conf.d/50-server.cnf <<'EOF'
[mysqld]
datadir = /var/lib/mysql
socket = /var/run/mysqld/mysqld.sock
pid-file = /var/run/mysqld/mysqld.pid
bind-address = 127.0.0.1
log-error = /var/log/mysql/error.log

# Connection limits
max_connections = 25
thread_cache_size = 4
table_open_cache = 64
table_definition_cache = 400

# Disable expensive features
performance_schema = OFF
skip-name-resolve

# InnoDB with absolute minimal threads
innodb_buffer_pool_size = 32M
innodb_log_buffer_size = 2M
innodb_read_io_threads = 1
innodb_write_io_threads = 1
innodb_purge_threads = 1
innodb_page_cleaners = 1
innodb_use_native_aio = 0
innodb_flush_method = fsync

# Disable background tasks that spawn threads
innodb_buffer_pool_dump_at_shutdown = 0
innodb_buffer_pool_load_at_startup = 0
EOF

# Initialize MySQL datadir if it doesn't exist (MariaDB was built without initialized data)
echo "Initializing MariaDB datadir..."
if [ ! -d /var/lib/mysql/mysql ]; then
    echo "MySQL datadir not initialized. Running mysql_install_db..."
    mysql_install_db --user=mysql --datadir=/var/lib/mysql --skip-name-resolve
    if [ $? -ne 0 ]; then
        echo "WARNING: mysql_install_db failed, attempting to proceed anyway..."
    fi
fi

# Fix permissions
chown -R mysql:mysql /var/lib/mysql /var/run/mysqld
chmod 755 /var/lib/mysql /var/run/mysqld

# Start mysql using the correct service name for Ubuntu 20.04
echo "Starting mysql..."

service mysql start
if [ $? -ne 0 ]; then
    echo "mysql failed to start, trying again..."
    sleep 5
    service mysql start
    if [ $? -ne 0 ]; then
        echo "mysql could not be started. Exiting."
        exit 1
    fi
fi

# Wait for MySQL to be ready
sleep 5
if ! mysqladmin ping -h localhost --silent 2>/dev/null; then
    echo "mysql failed to start, trying again..."
    service mysql restart
    sleep 10
fi

# Set up database and user (first time only)
echo "Setting up database..."
mysql -e "CREATE DATABASE IF NOT EXISTS wiki_db;" 2>/dev/null || true
mysql -e "CREATE USER IF NOT EXISTS 'wiki_user'@'localhost' IDENTIFIED BY 'Easter-Unmixable2-Previous';" 2>/dev/null || true
mysql -e "GRANT ALL PRIVILEGES ON wiki_db.* TO 'wiki_user'@'localhost';" 2>/dev/null || true
mysql -e "FLUSH PRIVILEGES;" 2>/dev/null || true

# Initialize MediaWiki
echo "Initializing MediaWiki..."
chmod +x /ctf/config/init_mediawiki.sh
/ctf/config/init_mediawiki.sh

# Set up SSH host keys if they don't exist
if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
    echo "Generating SSH host keys..."
    ssh-keygen -A
fi

# Initialize WordPress if needed
echo "Initializing WordPress..."
chmod +x /ctf/config/init_blog.sh
/ctf/config/init_blog.sh

# Set up SSH access
echo "Setting up SSH..."
mkdir -p /var/run/sshd

# Stop services before letting supervisor take over
service mysql stop
sleep 2
rm -f /var/run/mysqld/mysqld.pid /var/lib/mysql/*.pid
mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld

while mysqladmin ping -h localhost --silent; do
    echo "mysql failed to stop, trying again..."
    service mysql stop
    sleep 10
done
echo "MySQL service is down. Starting through supervisor..."

# AC - Staging root flag
echo "[+] Staging Final Token"
echo $ROOT_FLAG > /flag.txt && chown root:root /flag.txt && chmod 400 /flag.txt
echo "[+] Final Flag Staged"
export ROOT_FLAG=
echo "[+] Unset Final Flag variable"

unset ROOT_FLAG
unset USER_PASSWORD

# Start all services via supervisor
echo "Starting all services..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf
