#!/bin/bash

set -e
trap 'echo "Command failed on line $LINENO"' ERR

LOG_FILE="/home/ubuntu/deployment.log"

log_message() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
}

handle_error() {
    local message=$1
    local exit_code=$2
    echo "$(date +'%Y-%m-%d %H:%M:%S') - ERROR - $message" >> "$LOG_FILE"
    exit $exit_code
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

install_package() {
    local package=$1
    local command_check=$2
    if ! command_exists "$command_check"; then
        echo "Installing $package..."
        apt-get install -y "$package"
        if ! command_exists "$command_check"; then
            handle_error "Installation of $package failed. Please check the logs." 1
        fi
    else
        echo "$package is already installed."
    fi
}

validate_domain_name() {
    local domain_name=$1
    local regex="^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if ! [[ $domain_name =~ $regex ]]; then
        echo "Invalid domain name format. Please provide a valid domain name."
        exit 1
    fi
}

validate_username() {
    local username=$1
    local regex="^[a-z_][a-z0-9_-]*$"
    if ! [[ $username =~ $regex ]]; then
        echo "Invalid username format. Please provide a valid username."
        exit 1
    fi
}

validate_password() {
    local password=$1
    local regex="^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*()_+]).{8,}$"
    if ! [[ $password =~ $regex ]]; then
        echo "Invalid password. Password should be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        exit 1
    fi
}

validate_database_name() {
    local db_name=$1
    local regex="^[a-zA-Z0-9_]+$"
    if ! [[ $db_name =~ $regex ]]; then
        echo "Invalid database name format. Please provide a valid database name."
        exit 1
    fi
}

prompt_input_secure() {
    local prompt=$1
    local variable=$2
    read -rsp "$prompt" "$variable"
    echo
}

prompt_input() {
    local prompt=$1
    local variable=$2
    read -p "$prompt" "$variable"
}

install_dependencies() {
    local php_version=$1
    local dependencies=(
        "nginx"
        "git"
        "mysql-server"
    )

    local php_extensions=(
        "php${php_version}-fpm"
        "php${php_version}-mysql"
        "php${php_version}-mbstring"
        "php${php_version}-xml"
        "php${php_version}-zip"
        "php${php_version}-bcmath"
        "php${php_version}-tokenizer"
    )

    echo "Updating package list..."
    apt-get update

    for dep in "${dependencies[@]}"; do
        local package="${dep}"
        local check_command="${dep}"
        if [[ "$dep" == "php-fpm" ]]; then
            check_command="php"
        fi
        install_package "$package" "$check_command"
    done

    for ext in "${php_extensions[@]}"; do
        install_package "$ext" "$ext"
    done

    echo "Installing composer..."
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    if ! command_exists composer; then
        handle_error "Composer installation failed. Please check the logs." 1
    fi

    echo "Installing certbot..."
    apt-get install certbot python3-certbot-nginx
    if ! command_exists certbot; then
        handle_error "Certbot installation failed. Please check the logs." 1
    fi
}

check_php_version() {
    local php_version=$1
    local installed_php_version=$(php -v | head -n 1 | cut -d " " -f 2 | cut -d "." -f 1,2)

    if [ "$php_version" != "$installed_php_version" ]; then
        echo "PHP version $php_version not installed. Please check the logs."
        exit 1
    fi
}

create_user() {
    local username=$1
    local password=$2

    echo "Creating user..."
    if id "$username" >/dev/null 2>&1; then
        log_message "User $username already exists"
    else
        useradd -m -s /bin/bash "$username"
        echo "$username:$password" | chpasswd
        log_message "User $username created"
    fi
}

create_website_directory() {
    local username=$1
    local website_dir=$2

    echo "Creating website directory..."
    mkdir -p "$website_dir"
    chown -R "$username:$username" "$website_dir"
    chmod -R 755 "$website_dir"
    log_message "Website directory $website_dir created"
}

create_database() {
    local db_name=$1
    local db_user=$2
    local db_pass=$3
    local mysql_root_password=$4

    echo "Creating database..."
    local query_status=$(mysql -u root -p$mysql_root_password <<-EOF
    CREATE DATABASE IF NOT EXISTS \`$db_name\`;
    CREATE USER '\`$db_user\`'@'localhost' IDENTIFIED BY '\`$db_pass\`';
    GRANT ALL PRIVILEGES ON \`$db_name\`.* TO '\`$db_user\`'@'localhost';
    FLUSH PRIVILEGES;
EOF
)
    if [ $? -eq 0 ]; then
        log_message "Database $db_name and user $db_user created"
    else
        echo "Database creation failed. Please check the logs."
        exit 1
    fi
}

clone_repository() {
    local repository=$1
    local website_dir=$2

    echo "Cloning repository..."
    git clone "$repository" "$website_dir"
    if [ $? -eq 0 ]; then
        log_message "Repository $repository cloned to $website_dir"
    else
        echo "Repository cloning failed. Please check the logs."
        exit 1
    fi
}

configure_nginx() {
    local server_name=$1
    local website_dir=$2
    local php_version=$3

    local nginx_config=$(cat <<-EOF
    server {
        listen 80;
        server_name $server_name;
        root $website_dir/public;

        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-XSS-Protection "1; mode=block";
        add_header X-Content-Type-Options "nosniff";

        index index.html index.htm index.php;

        charset utf-8;

        location / {
            try_files \$uri \$uri/ /index.php?\$query_string;
        }

        location = /favicon.ico { access_log off; log_not_found off; }
        location = /robots.txt  { access_log off; log_not_found off; }

        error_page 404 /index.php;

        location ~ \.php$ {
            include snippets/fastcgi-php.conf;
            fastcgi_pass unix:/var/run/php/php$php_version-fpm.sock;
        }

        location ~ /\.(?!well-known).* {
            deny all;
        }
    }
EOF
)

    echo "$nginx_config" > "/etc/nginx/sites-available/$server_name"
    ln -s "/etc/nginx/sites-available/$server_name" "/etc/nginx/sites-enabled/$server_name"
    systemctl restart nginx
    log_message "Nginx configured for $server_name"
}

install_composer_dependencies() {
    local directory=$1

    echo "Installing Composer dependencies..."
    pushd "$directory"
    composer install --no-dev --optimize-autoloader
    popd
    log_message "Composer dependencies installed"
}

setup_ssl() {
    local server_name=$1
    local email_address=$2

    echo "Setting up SSL..."
    certbot --nginx -d "$server_name" --non-interactive --agree-tos --email "$email_address"
    if [ $? -eq 0 ]; then
        log_message "SSL certificate installed for $server_name"
    else
        echo "SSL certificate installation failed. Please check the logs."
        exit 1
    fi
}

laravel_post_deployment() {
    local directory=$1
    local domain_name=$2
    local db_name=$3
    local db_user=$4
    local db_pass=$5
    local app_name=${directory##*/}

    echo "Post-deployment Laravel setup..."
    pushd "$directory"
    cp .env.example .env
    chown -R www-data:www-data storage bootstrap/cache
    chmod -R 755 storage bootstrap/cache
    php artisan key:generate
    php artisan migrate --force
    php artisan config:cache
    php artisan route:cache
    php artisan view:cache
    sed -i "s/APP_NAME=.*/APP_NAME=$app_name/g" .env
    sed -i "s/APP_ENV=.*/APP_ENV=production/g" .env
    sed -i "s/APP_DEBUG=.*/APP_DEBUG=false/g" .env
    sed -i "s/APP_URL=.*/APP_URL=https:\/\/$domain_name/g" .env
    sed -i "s/DB_DATABASE=.*/DB_DATABASE=$db_name/g" .env
    sed -i "s/DB_USERNAME=.*/DB_USERNAME=$db_user/g" .env
    sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$db_pass/g" .env
    popd
    log_message "Post-deployment Laravel setup complete"
}


main() {
    local username=""
    local password=""
    local domain_name=""
    local email_address=""
    local mysql_root_password=""
    local mysql_root_password_confirm=""
    local db_name=""
    local db_user=""
    local db_pass=""
    local php_version=""
    local repository=""
    local website_dir="/var/www/html"

    prompt_input "Enter your desired username: " username
    validate_username "$username"
    prompt_input_secure "Enter your desired password: " password
    validate_password "$password"
    prompt_input "Enter your domain name: " domain_name
    validate_domain_name "$domain_name"
    prompt_input "Enter your email address: " email_address
    prompt_input_secure "Enter MySQL root password: " mysql_root_password
    prompt_input_secure "Confirm MySQL root password: " mysql_root_password_confirm
    if [ "$mysql_root_password" != "$mysql_root_password_confirm" ]; then
        handle_error "MySQL root passwords do not match." 1
    fi
    prompt_input "Enter your desired database name: " db_name
    validate_database_name "$db_name"
    prompt_input "Enter your desired database user: " db_user
    validate_username "$db_user"
    prompt_input_secure "Enter your desired database password: " db_pass
    validate_password "$db_pass"
    prompt_input "Enter your PHP version (i.e., 7.4, 8.0): " php_version
    prompt_input "Enter the URL of your Laravel project repository: " repository

    website_dir="$website_dir/$username"
    install_dependencies "$php_version"
    check_php_version "$php_version"
    create_user "$username" "$password"
    create_website_directory "$username" "$website_dir"
    create_database "$db_name" "$db_user" "$db_pass" "$mysql_root_password"
    clone_repository "$repository" "$website_dir"
    configure_nginx "$domain_name" "$website_dir" "$php_version"
    install_composer_dependencies "$website_dir"
    setup_ssl "$domain_name" "$email_address"
    laravel_post_deployment "$website_dir" "$domain_name" "$db_name" "$db_user" "$db_pass"
}

main

exit 0
