#!/bin/bash

#########################################################
#                Nextcloud Installation                 #
#                Author: Kristian Gasic                 #
#                Forked by bennyp3333                   #
#########################################################

VERSION="1.2"
LOG_FILE="install.log"
DATA_DIR="/mnt/nextcloud-data"
DB_NAME="nextcloud"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IP_ADDRESS=$(hostname -I | awk '{print $1}')

get_user_input() {
    echo "====Nextcloud Installer v${VERSION}====" | tee -a "$LOG_FILE"
    read -p "Enter MariaDB Username: " MARIADB_USER
    read -p "Enter Subdomain (e.g., nextcloud.example.com): " SUBDOMAIN
}

create_install_log() {
    cat << EOF > "$LOG_FILE"
Nextcloud Installation Log
===========================
MariaDB Username: ${MARIADB_USER}
Database Name: ${DB_NAME}
IP Address: ${IP_ADDRESS}
Subdomain: ${SUBDOMAIN}
Data Directory: ${DATA_DIR}
================================================
EOF
}

install_packages() {
    echo "Updating system packages..." | tee -a "$LOG_FILE"
    sudo apt update && sudo apt upgrade -y || {
        echo "Failed to update packages" | tee -a "$LOG_FILE";
        exit 1;
    }

    echo "Installing base packages..." | tee -a "$LOG_FILE"
    sudo apt install \
    apache2 \
    mariadb-server \
    redis-server \
    software-properties-common \
    wget \
    zip \
    unzip \
    exif \
    imagemagick \
    ffmpeg \
    libreoffice \
    pwgen \
    -y || { echo "Failed to install base packages" | tee -a "$LOG_FILE"; exit 1; }

    echo "Adding PHP repository..." | tee -a "$LOG_FILE"
    sudo add-apt-repository ppa:ondrej/php -y || {
        echo "Failed to add PHP repository" | tee -a "$LOG_FILE";
        exit 1;
    }
    sudo apt update || {
        echo "Failed to update package list after adding PHP repository" | tee -a "$LOG_FILE";
        exit 1;
    }

    echo "Installing PHP 8.3 and required modules..." | tee -a "$LOG_FILE" 
    sudo apt install \
    php8.3 \
    php8.3-bcmath \
    php8.3-bz2 \
    php8.3-cli \
    php8.3-common \
    php8.3-curl \
    php8.3-dev \
    php8.3-fpm \
    php8.3-gd \
    php8.3-gmp \
    php8.3-imagick \
    php8.3-intl \
    php8.3-mbstring \
    php8.3-mysql \
    php8.3-redis \
    php8.3-soap \
    php8.3-xml \
    php8.3-zip \
    php8.3-opcache \
    php8.3-apcu \
    libapache2-mod-fcgid \
    -y || { echo "Failed to install PHP packages" | tee -a "$LOG_FILE"; exit 1; }

    echo "Pakages installed successfully." | tee -a "$LOG_FILE"
}

setup_mariadb() {
    echo "Starting and securing MariaDB..." | tee -a "$LOG_FILE"
    sudo systemctl start mariadb || { echo "Failed to start MariaDB" | tee -a "$LOG_FILE"; exit 1; }

    # Change the MariaDB settings to the recommended READ-COMITTED and binlog format ROW
    sudo bash -c 'cat > /etc/mysql/conf.d/nextcloud.cnf <<EOF
[mysqld]
transaction_isolation = READ-COMMITTED
binlog_format = ROW
EOF'
    sudo systemctl restart mariadb || { echo "Failed to restart MariaDB" | tee -a "$LOG_FILE"; exit 1; }

    # Verify database settings
    echo "Verifying MariaDB settings..." | tee -a "$LOG_FILE"
    MYSQL_OUTPUT=$(sudo mysql -u root -e "
SELECT @@global.tx_isolation;
SELECT @@global.binlog_format;" 2>&1)

    echo "$MYSQL_OUTPUT" | tee -a "$LOG_FILE"

    # Check for MySQL errors
    if echo "$MYSQL_OUTPUT" | grep -iq "ERROR"; then
        echo "Failed changing database settings" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "MariaDB settings updated successfully." | tee -a "$LOG_FILE"

    # Generate a strong password
    MARIADB_PASSWORD=$(pwgen -s 32 1)
    if [ $? -ne 0 ] || [ -z "$MARIADB_PASSWORD" ]; then
        echo "Failed to generate password" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "Generated password: ${MARIADB_PASSWORD}" | tee -a "$LOG_FILE"

    # Check if the user exists by querying the MySQL user table
    USER_EXISTS=$(sudo mysql -u root -B -N -e "
SELECT EXISTS(SELECT 1 FROM mysql.user WHERE user = '${MARIADB_USER}' AND host = 'localhost');
" 2>&1)

    # Check if the user exists and drop it if necessary
    if [ "$USER_EXISTS" -eq 1 ]; then
        echo "User ${MARIADB_USER} already exists." | tee -a "$LOG_FILE"

        # Set database user and password if already installed
        INSTALL_STATUS=$(sudo -u www-data php /var/www/nextcloud/occ status --output=json | grep -o '"installed":true')
        if [ -n "$INSTALL_STATUS" ]; then
            echo "Nextcloud previously installed." | tee -a "$LOG_FILE"
            echo "Setting database user and password..." | tee -a "$LOG_FILE"
            sudo -u www-data php /var/www/nextcloud/occ config:system:set dbuser --value=${MARIADB_USER} || { 
                echo "Failed to set database user" | tee -a "$LOG_FILE"
                exit 1
            }
            sudo -u www-data php /var/www/nextcloud/occ config:system:set dbpassword --value=${MARIADB_PASSWORD} || { 
                echo "Failed to set database password" | tee -a "$LOG_FILE"
                exit 1
            }
        fi

        echo "Dropping user ${MARIADB_USER}..." | tee -a "$LOG_FILE"
        sudo mysql -u root -e "DROP USER '${MARIADB_USER}'@'localhost';" 2>&1
    fi

    # Create the user, database and set privileges
    echo "Creating database user ${MARIADB_USER} and database ${DB_NAME}..." | tee -a "$LOG_FILE"
    MYSQL_OUTPUT=$(sudo mysql -u root -e "
CREATE USER '${MARIADB_USER}'@'localhost' IDENTIFIED BY '${MARIADB_PASSWORD}';
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${MARIADB_USER}'@'localhost';
FLUSH PRIVILEGES;
" 2>&1)

    # Check for MySQL errors
    if echo "$MYSQL_OUTPUT" | grep -iq "ERROR"; then
        echo "Database setup failed" | tee -a "$LOG_FILE"
        exit 1
    fi
    
    echo "MariaDB database and user setup completed successfully!" | tee -a "$LOG_FILE"
    echo "Remember to run: sudo mariadb-secure-installation"
}

download_nextcloud() {
    echo "Setting up Nextcloud data directory..." | tee -a "$LOG_FILE"
    sudo mkdir -p "${DATA_DIR}"
    sudo chown -R www-data:www-data "${DATA_DIR}"
    sudo chmod 750 "${DATA_DIR}"

    # Download and set up Nextcloud
    echo "Downloading Nextcloud..." | tee -a "$LOG_FILE"

    wget -O latest.zip https://download.nextcloud.com/server/releases/latest.zip || { 
        echo "Failed to download Nextcloud" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    wget -O latest.zip.sha256 https://download.nextcloud.com/server/releases/latest.zip.sha256 || { 
        echo "Failed to download Nextcloud checksum" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    # Verify the checksum using absolute paths
    echo "Verifying checksum..." | tee -a "$LOG_FILE"
    sha256sum -c latest.zip.sha256 --ignore-missing 2>&1 | tee -a "$LOG_FILE"

    if [ $? -ne 0 ]; then
        echo "Checksum verification failed! Exiting..." | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "Checksum verified successfully!" | tee -a "$LOG_FILE"

    # Extract Nextcloud
    echo "Extracting Nextcloud..." | tee -a "$LOG_FILE"
    sudo unzip -oq latest.zip -d /var/www/ || { 
        echo "Failed to extract Nextcloud" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    # Set correct permissions
    echo "Setting correct permissions..." | tee -a "$LOG_FILE"
    sudo chown -R www-data:www-data /var/www/nextcloud
    sudo chmod -R 755 /var/www/nextcloud

    echo "Nextcloud download completed successfully!" | tee -a "$LOG_FILE"
}

create_php_config() {
    local file_path="$1"
    local content="$2"
    sudo bash -c "cat > ${file_path} <<EOF
${content}
EOF"
    if [ $? -ne 0 ]; then
        echo "Failed to create or write to ${file_path}" | tee -a "$LOG_FILE"
        exit 1
    fi
    echo "Successfully configured ${file_path}" | tee -a "$LOG_FILE"
}

configure_php() {
    # Configure PHP FPM and MPM
    echo "Configuring PHP FPM and MPM..." | tee -a "$LOG_FILE"
    sudo systemctl stop apache2 || { echo "Failed to stop Apache" | tee -a "$LOG_FILE"; exit 1; }
    sudo a2dissite '*' || { echo "Failed to disable sites" | tee -a "$LOG_FILE"; exit 1; }
    sudo a2dismod php8.3 mpm_prefork mpm_worker | tee -a "$LOG_FILE"
    sudo a2enmod mpm_event proxy proxy_fcgi setenvif | tee -a "$LOG_FILE"
    sudo a2enconf php8.3-fpm | tee -a "$LOG_FILE"
    sudo systemctl restart apache2 || { echo "Failed to restart Apache" | tee -a "$LOG_FILE"; exit 1; }
    echo "Testing Apache configuration..." | tee -a "$LOG_FILE"
    sudo apachectl configtest 2>&1 | tee -a "$LOG_FILE"
    echo "Verifying active MPM module..." | tee -a "$LOG_FILE"
    sudo apachectl -M 2>&1 | grep 'mpm' | tee -a "$LOG_FILE"
    echo "Verifying active Proxy module..." | tee -a "$LOG_FILE"
    sudo apachectl -M | grep 'proxy' | tee -a "$LOG_FILE"

    # Uncomment environment variables in PHP FPM config
    echo "Uncommenting environment variables in PHP FPM config..." | tee -a "$LOG_FILE"
    if [ -f /etc/php/8.3/fpm/pool.d/www.conf ]; then
        sudo sed -i "s/^;env\[HOSTNAME\] =.*/env[HOSTNAME] = \$HOSTNAME/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^;env\[PATH\] =.*/env[PATH] = \/usr\/local\/bin:\/usr\/bin:\/bin/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^;env\[TMP\] =.*/env[TMP] = \/tmp/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^;env\[TMPDIR\] =.*/env[TMPDIR] = \/tmp/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^;env\[TEMP\] =.*/env[TEMP] = \/tmp/" /etc/php/8.3/fpm/pool.d/www.conf
        # Update server counts
        sudo sed -i "s/^pm.max_children = [0-9]\+/pm.max_children = 64/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^pm.start_servers = [0-9]\+/pm.start_servers = 16/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^pm.min_spare_servers = [0-9]\+/pm.min_spare_servers = 16/" /etc/php/8.3/fpm/pool.d/www.conf
        sudo sed -i "s/^pm.max_spare_servers = [0-9]\+/pm.max_spare_servers = 32/" /etc/php/8.3/fpm/pool.d/www.conf
    fi
    sudo systemctl reload php8.3-fpm.service || { echo "Failed to reload PHP FPM" | tee -a "$LOG_FILE"; exit 1; }

    echo "PHP FPM configured successfully!" | tee -a "$LOG_FILE"

    # Configure PHP Opcache, APCU, and Upload Settings
    echo "Configuring PHP Opcache, APCU, and Upload settings..." | tee -a "$LOG_FILE"
    sudo mkdir -p /etc/php/8.3/apache2/conf.d || { 
        echo "Failed to create PHP config directory" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    # Setup Opcache
    echo "Setting up PHP Opcache..." | tee -a "$LOG_FILE"
    OPCACHE_CONFIG=$(cat <<EOF
zend_extension=opcache.so
opcache.enable=1
opcache.enable_cli=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.revalidate_freq=1
opcache.save_comments=1
opcache.jit=on
opcache.jit=1255
opcache.jit_buffer_size=128M
EOF
    )
    create_php_config "/etc/php/8.3/fpm/conf.d/10-opcache.ini" "$OPCACHE_CONFIG"
    #create_php_config "/etc/php/8.3/apache2/conf.d/10-opcache.ini" "$OPCACHE_CONFIG"
    #create_php_config "/etc/php/8.3/cli/conf.d/10-opcache.ini" "$OPCACHE_CONFIG"

    # Setup Upload settings
    echo "Configuring PHP upload settings..." | tee -a "$LOG_FILE"
    UPLOAD_CONFIG=$(cat <<EOF
memory_limit=2G
upload_max_filesize=50G
post_max_size=0
max_execution_time=3600
max_input_time=3600
EOF
    )
    create_php_config "/etc/php/8.3/fpm/conf.d/20-upload.ini" "$UPLOAD_CONFIG"
    #create_php_config "/etc/php/8.3/apache2/conf.d/20-upload.ini" "$UPLOAD_CONFIG"
    #create_php_config "/etc/php/8.3/cli/conf.d/20-upload.ini" "$UPLOAD_CONFIG"

    # Setup APCU
    echo "Setting up PHP APCU..." | tee -a "$LOG_FILE"
    APCU_CONFIG=$(cat <<EOF
extension=apcu.so
apc.enabled=1
apc.enable_cli=1
EOF
    )
    create_php_config "/etc/php/8.3/fpm/conf.d/20-apcu.ini" "$APCU_CONFIG"
    #create_php_config "/etc/php/8.3/apache2/conf.d/20-apcu.ini" "$APCU_CONFIG"
    #create_php_config "/etc/php/8.3/cli/conf.d/20-apcu.ini" "$APCU_CONFIG"

    echo "Configuring Redis..." | tee -a "$LOG_FILE"
    sudo usermod -a -G redis www-data
    if [ -f /etc/redis/redis.conf ]; then
        sudo sed -i "s/^port 6379/port 0/" /etc/redis/redis.conf || { echo "Failed to configure Redis port" | tee -a "$LOG_FILE"; exit 1; }
        sudo sed -i "s/^# *unixsocketperm 700/unixsocketperm 770/" /etc/redis/redis.conf || { echo "Failed to set unixsocket permissions" | tee -a "$LOG_FILE"; exit 1; }
        sudo sed -i "s/^# *unixsocket/unixsocket/" /etc/redis/redis.conf || { echo "Failed to uncomment unixsocket" | tee -a "$LOG_FILE"; exit 1; }
    else
        echo "Redis configuration file not found at /etc/redis/redis.conf" | tee -a "$LOG_FILE"
        exit 1
    fi

    REDIS_SETTINGS=("apc.enable_cli=1" "redis.session.locking_enabled=1" "redis.session.lock_retries=-1" "redis.session.lock_wait_time=10000")
    EXISTING_LINES=$(grep -Fxc "${REDIS_SETTINGS[0]}" "/etc/php/8.3/fpm/php.ini")

    if [ "$EXISTING_LINES" -eq 0 ]; then
        sudo sed -i "1a ${REDIS_SETTINGS[0]}\n${REDIS_SETTINGS[1]}\n${REDIS_SETTINGS[2]}" "/etc/php/8.3/fpm/php.ini" || {
            echo "Failed to add redis settings to php-fpm" | tee -a "$LOG_FILE";
            exit 1;
        }
    else
        echo "Redis settings already exist, skipping modification." | tee -a "$LOG_FILE";
    fi

    sudo service php8.3-fpm restart || { echo "Failed to restart PHP FPM" | tee -a "$LOG_FILE"; exit 1; }
    sudo systemctl restart apache2 || { echo "Failed to restart Apache" | tee -a "$LOG_FILE"; exit 1; }
    sudo systemctl restart redis-server || { echo "Failed to restart Redis" | tee -a "$LOG_FILE"; exit 1; }
    echo "Redis configured successfully!" | tee -a "$LOG_FILE"

    # Verify PHP configuration
    # echo "Verifying PHP settings..." | tee -a "$LOG_FILE"
    # echo "<?php phpinfo(); ?>" | sudo tee /var/www/nextcloud/info.php > /dev/null

    echo "PHP configuration completed successfully!" | tee -a "$LOG_FILE"
}

configure_apache() {
    echo "Configuring Apache for Nextcloud..." | tee -a "$LOG_FILE"
    
    # Create Apache VirtualHost configuration for Nextcloud
    TEMPLATE_FILE="$SCRIPT_DIR/apache-site-template.conf"
    TARGET_FILE="/etc/apache2/sites-available/nextcloud.conf"

    # Check if the template file exists
    if [[ ! -f "$TEMPLATE_FILE" ]]; then
        echo "Template file not found: $TEMPLATE_FILE" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Replace placeholders in the template and write to the target file
    sudo sed "s|{{SUBDOMAIN}}|$SUBDOMAIN|g" "$TEMPLATE_FILE" | sudo tee "$TARGET_FILE" > /dev/null

    # Verify if the operation succeeded
    if [[ $? -eq 0 ]]; then
        echo "Configuration file created successfully: $TARGET_FILE" | tee -a "$LOG_FILE"
    else
        echo "Failed to create configuration file" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Enable site and necessary Apache modules
    sudo a2ensite nextcloud.conf || { echo "Failed to enable nextcloud site" | tee -a "$LOG_FILE"; exit 1; }
    sudo a2enmod rewrite headers env dir mime setenvif ssl http2 || { echo "Failed to enable necessary Apache modules" | tee -a "$LOG_FILE"; exit 1; }
    
    # Disable default site and remove old HTML files
    sudo a2dissite 000-default.conf || { echo "Failed to disable default site" | tee -a "$LOG_FILE"; exit 1; }
    sudo rm -rf /var/www/html || { echo "Failed to remove old web root files" | tee -a "$LOG_FILE"; exit 1; }
    
    # Reload Apache to apply changes
    sudo systemctl reload apache2 || { echo "Failed to reload Apache" | tee -a "$LOG_FILE"; exit 1; }
    
    # Test Apache configuration
    echo "Testing Apache configuration..." | tee -a "$LOG_FILE"
    sudo apachectl configtest 2>&1 | tee -a "$LOG_FILE" || { echo "Apache configuration test failed" | tee -a "$LOG_FILE"; exit 1; }

    echo "Apache configuration for Nextcloud completed successfully!" | tee -a "$LOG_FILE"
}

configure_firewall() {
    echo "Configuring Firewall..." | tee -a "$LOG_FILE"

    # Install dependencies
    if ! apt install iptables-persistent netfilter-persistent -y; then
        echo "Error: Failed to install iptables-persistent and netfilter-persistent" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Enable and start firewall service
    if ! systemctl enable netfilter-persistent; then
        echo "Error: Failed to enable netfilter-persistent" | tee -a "$LOG_FILE"
        exit 1
    fi

    if ! systemctl start netfilter-persistent; then
        echo "Error: Failed to start netfilter-persistent" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Flush all existing rules
    if ! iptables -F || ! iptables -X || ! iptables -t nat -F || ! iptables -t nat -X || ! iptables -t mangle -F || ! iptables -t mangle -X; then
        echo "Error: Failed to flush iptables rules" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Define rules
    RULES=(
        '-A INPUT -i lo -j ACCEPT'                   # Allow loopback
        '-A OUTPUT -o lo -j ACCEPT'
        '-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' # Allow existing connections
        '-A INPUT -s 192.168.1.0/24 -j ACCEPT'       # Local network access
        '-A OUTPUT -j ACCEPT'                        # Allow all outgoing traffic
        '-A INPUT -p tcp --dport 22 -j ACCEPT'       # SSH
        '-A INPUT -p tcp --dport 80 -j ACCEPT'       # HTTP
        '-A INPUT -p tcp --dport 443 -j ACCEPT'      # HTTPS
        '-A INPUT -p icmp -j ACCEPT'                 # ICMP (ping)
        '-A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j DROP' # SYN flood protection
        '-A INPUT -p tcp --tcp-flags ALL NONE -j DROP'
        '-A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP'
        '-A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP'
        '-A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 3 -j ACCEPT' # Ping flood protection
        '-A INPUT -s 10.0.0.0/8 -j DROP'             # IP Spoofing protection
        '-A INPUT -s 172.16.0.0/12 -j DROP'
        '-A INPUT -s 127.0.0.0/8 -j DROP'
        '-A INPUT -s 224.0.0.0/4 -j DROP'
        '-A INPUT -s 240.0.0.0/5 -j DROP'
        '-A INPUT -s 0.0.0.0/8 -j DROP'
        '-A INPUT -s 169.254.0.0/16 -j DROP'
        '-A INPUT -m limit --limit 5/min -j LOG --log-prefix iptables_denied: --log-level 7' # Log dropped packets
        '-A INPUT -j DROP'                            # Drop all other inbound traffic
    )

    # Apply rules
    for RULE in "${RULES[@]}"; do
        if ! iptables $RULE; then
            echo "Error: Failed to apply rule: $RULE" | tee -a "$LOG_FILE"
            exit 1
        fi
    done

    # Save rules
    if ! iptables-save > /etc/iptables/rules.v4; then
        echo "Error: Failed to save iptables rules" | tee -a "$LOG_FILE"
        exit 1
    fi

    echo "Firewall configuration completed successfully!" | tee -a "$LOG_FILE"
}

install_nextcloud() {
    # Install nextcloud depending on if its been installed already
    INSTALL_STATUS=$(sudo -u www-data php /var/www/nextcloud/occ status --output=json | grep -o '"installed":true')

    if [ -n "$INSTALL_STATUS" ]; then
        echo "Nextcloud previously installed." | tee -a "$LOG_FILE"
    else
        echo "Running Nextcloud CLI installer..." | tee -a "$LOG_FILE"
        sudo -u www-data php /var/www/nextcloud/occ maintenance:install \
            --database "mysql" \
            --database-name "${DB_NAME}" \
            --database-user "${MARIADB_USER}" \
            --database-pass "${MARIADB_PASSWORD}" \
            --admin-user "admin" \
            --admin-pass "admin-password" \
            --data-dir="${DATA_DIR}" || { 
                echo "Nextcloud CLI installation failed" | tee -a "$LOG_FILE";
                exit 1;
            }
    fi

    echo "Running Nextcloud CLI repair..." | tee -a "$LOG_FILE"
    sudo -u www-data php /var/www/nextcloud/occ maintenance:repair --include-expensive || { 
        echo "Nextcloud CLI repair failed" | tee -a "$LOG_FILE";
        exit 1;
    }

    # Set trusted domain to resolve the admin error
    echo "Configuring trusted domains..." | tee -a "$LOG_FILE"
    sudo -u www-data php /var/www/nextcloud/occ config:system:set overwrite.cli.url --value=https://${SUBDOMAIN}/ \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set htaccess.RewriteBase --value=/ \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set trusted_domains 0 --value=localhost \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set trusted_domains 1 --value=${IP_ADDRESS} \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set trusted_domains 2 --value=${SUBDOMAIN} || { 
        echo "Failed to configure trusted domains" | tee -a "$LOG_FILE";
        exit 1;
    }

    echo "Configuring nextcloud config to use apcu and redis..." | tee -a "$LOG_FILE"
    sudo -u www-data php /var/www/nextcloud/occ config:system:set memcache.local --value='\OC\Memcache\APCu' \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set filelocking.enabled --value=true --type=boolean \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set memcache.locking --value='\OC\Memcache\Redis' \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set redis host --value='/run/redis/redis-server.sock' \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set redis port --value=0 --type=integer \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set redis dbindex --value=0 --type=integer \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set redis password --value='' \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set redis timeout --value=1.5 --type=float || {
        echo "Failed to configure nextcloud config" | tee -a "$LOG_FILE";
        exit 1;
    }

    echo "Configuring other nextcloud config settings..." | tee -a "$LOG_FILE"
    sudo -u www-data php /var/www/nextcloud/occ config:system:set maintenance_window_start --type=integer --value=1 \
    && sudo -u www-data php /var/www/nextcloud/occ config:system:set default_phone_region --value='US' \
    && sudo -u www-data php /var/www/nextcloud/occ config:app:set --value=yes serverinfo phpinfo || {
        echo "Failed to configure nextcloud config" | tee -a "$LOG_FILE";
        exit 1;
    }
    
    sudo -u www-data php /var/www/nextcloud/occ maintenance:update:htaccess || { echo "Failed to update htaccess" | tee -a "$LOG_FILE"; exit 1; }

    echo "Nextcloud installation completed successfully!" | tee -a "$LOG_FILE"
}

install_ssl() {
    # Install Certbot and Cloudflare plugin
    sudo apt install -y certbot python3-certbot-apache python3-certbot-dns-cloudflare || { 
        echo "Failed to install Certbot" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    # Define paths for SSL options file
    OPTIONS_FILE="$SCRIPT_DIR/options-ssl-apache.conf"
    TARGET_FILE="/etc/letsencrypt/options-ssl-apache.conf"

    # Ensure the source file exists
    if [[ ! -f "$OPTIONS_FILE" ]]; then
        echo "Template SSL options file not found: $OPTIONS_FILE" | tee -a "$LOG_FILE"
        exit 1
    fi

    # Move the SSL options file to the target location
    sudo cp "$OPTIONS_FILE" "$TARGET_FILE" || {
        echo "Failed to copy SSL options file" | tee -a "$LOG_FILE"
        exit 1
    }

    echo "SSL options file copied successfully to: $TARGET_FILE" | tee -a "$LOG_FILE"

    # Define token file path
    TOKEN_FILE="$HOME/.secrets/certbot/cloudflare.ini"

    # Check if API token file exists
    if [[ ! -f "$TOKEN_FILE" ]]; then
        echo "Cloudflare API token not found." | tee -a "$LOG_FILE"

        # Prompt for Cloudflare API token
        read -r -p "Enter Cloudflare API Token: " CLOUDFLARE_TOKEN

        # Validate token input
        if [[ -z "$CLOUDFLARE_TOKEN" ]]; then
            echo "Error: No API token provided. Exiting." | tee -a "$LOG_FILE"
            exit 1
        fi

        # Write token to file
        mkdir -p "$(dirname "$TOKEN_FILE")"
        echo "dns_cloudflare_api_token = ${CLOUDFLARE_TOKEN}" > "$TOKEN_FILE"
        chmod 600 "$TOKEN_FILE"

        echo "Getting new SSL certificate..." | tee -a "$LOG_FILE"
    else
        echo "Existing Cloudflare API token found." | tee -a "$LOG_FILE"

        # Ask user if they want to renew the certificate
        read -r -p "Would you like to renew the cert? (y/N): " RENEW_CERT
        if [[ "$RENEW_CERT" != "y" ]]; then
            echo "Skipping certificate renewal." | tee -a "$LOG_FILE"
            return
        fi

        echo "Renewing SSL certificate..." | tee -a "$LOG_FILE"
    fi

    # Obtain or renew SSL certificate
    sudo certbot certonly --dns-cloudflare \
        --dns-cloudflare-credentials "$TOKEN_FILE" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$SUBDOMAIN" || { 
            echo "Failed to obtain SSL certificate" | tee -a "$LOG_FILE"; 
            exit 1; 
        }

    # Reload Apache to apply changes
    sudo systemctl reload apache2 || { 
        echo "Failed to reload Apache after SSL installation" | tee -a "$LOG_FILE"; 
        exit 1; 
    }

    echo "SSL installation completed successfully!" | tee -a "$LOG_FILE"
}

configure_cron() {
    CRONJOB="*/5 * * * * php -f /var/www/nextcloud/cron.php --define apc.enable_cli=1"

    echo "$CRONJOB" | sudo crontab -u www-data -
    
    # Verify if the cron job exists in the crontab
    if sudo crontab -u www-data -l | grep -qF "$CRONJOB"; then
        echo "Cron configured successfully!" | tee -a "$LOG_FILE"
    else
        echo "Failed to configure cron!" | tee -a "$LOG_FILE"
        exit 1
    fi
}

log_results() {
    echo "===================== Completed! =====================" | tee -a "$LOG_FILE"
    echo "IP Address: $IP_ADDRESS" | tee -a "$LOG_FILE"
}

# TODO: Move install to respective scripts

# Run the script functions
create_install_log
get_user_input
install_packages
setup_mariadb
download_nextcloud
install_ssl
configure_php
configure_apache
configure_firewall
install_nextcloud
configure_cron
log_results