#!/bin/bash

set -e
trap 'echo "Command failed on line $LINENO"' ERR

LOG_FILE="/var/log/deployment.log"

log_message() {
    local message=$1
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $message" >> "$LOG_FILE"
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
            echo "Installation of $package failed. Please check the logs."
            exit 1
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
    local dependencies=(
        "php-fpm"
        "nginx"
        "git"
        "composer"
        "certbot"
        "mysql-server"
    )

    for dep in "${dependencies[@]}"; do
        local package="${dep}"
        local check_command="${dep}"
        if ! command_exists "$check_command"; then
            install_package "$package" "$check_command"
        else
            echo "$package is already installed."
        fi
    done
}

create_user() {
    local username=$1
    local password=$2

    echo "Creating user..."
    if id "$username" >/dev/null 2>&1; then
        log_message "User $username already exists"
    else
        echo "$password" | adduser "$username" --gecos "" >/dev/null 2>&1
        echo "$username:$password" | chpasswd
        log_message "User $username created"
    fi
}

create_website_directory() {
    local username=$1
    local website_dir=$2

    echo "Creating website directory..."
    if [ ! -d "$website_dir" ]; then
        mkdir -p "$website_dir"
        chown -R "$username:$username" "$website_dir"
        chmod -R 755 "$website_dir"
        log_message "Website directory $website_dir created"
    else
        log_message "Website directory $website_dir already exists"
    fi
}

create_database() {
    local db_name=$1
    local db_user=$2
    local db_pass=$3

    echo "Creating database..."
    mysql -u root <<-EOF
    CREATE DATABASE IF NOT EXISTS \`$db_name\`;
    CREATE USER '\`$db_user\`'@'localhost' IDENTIFIED BY '\`$db_pass\`';
    GRANT ALL PRIVILEGES ON \`$db_name\`.* TO '\`$db_user\`'@'localhost';
    FLUSH PRIVILEGES;
EOF
    log_message "Database $db_name and user $db_user created"
}

clone_repository() {
    local repository=$1
    local directory=$2

    echo "Cloning repository..."
    git clone "$repository" "$directory"
    log_message "Repository $repository cloned to $directory"
}

configure_nginx() {
    local server_name=$1
    local php_version=$2
    local website_dir=$3

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
            fastcgi_pass unix:/run/php/php$php_version-fpm.sock;
            fastcgi_param SCRIPT_FILENAME  \$document_root\$fastcgi_script_name;
            include fastcgi_params;
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
    log_message "SSL set up for $server_name"
}

laravel_post_deployment() {
    local directory=$1

    echo "Post-deployment Laravel setup..."
    pushd "$directory"
    php artisan key:generate
    php artisan migrate --force
    php artisan config:cache
    php artisan route:cache
    php artisan view:cache
    popd
    log_message "Laravel post-deployment setup finished"
}

main() {
    local domain_name username password db_name db_user db_pass php_version repository website_dir email_address

    prompt_input "Enter domain name: " domain_name
    validate_domain_name "$domain_name"

    prompt_input "Enter username: " username
    validate_username "$username"

    prompt_input_secure "Enter password: " password
    validate_password "$password"

    prompt_input "Enter database name: " db_name
    validate_database_name "$db_name"

    prompt_input "Enter database username: " db_user
    validate_username "$db_user"

    prompt_input_secure "Enter database password: " db_pass
    validate_password "$db_pass"

    prompt_input "Enter PHP version: " php_version

    prompt_input "Enter Git repository URL: " repository

    website_dir="/var/www/$domain_name"
    create_website_directory "$username" "$website_dir"

    prompt_input "Enter email address for SSL certificate: " email_address

    install_dependencies
    create_user "$username" "$password"
    create_database "$db_name" "$db_user" "$db_pass"
    clone_repository "$repository" "$website_dir"
    configure_nginx "$domain_name" "$php_version" "$website_dir"
    install_composer_dependencies "$website_dir"
    setup_ssl "$domain_name" "$email_address"
    laravel_post_deployment "$website_dir"
}

main

exit 0