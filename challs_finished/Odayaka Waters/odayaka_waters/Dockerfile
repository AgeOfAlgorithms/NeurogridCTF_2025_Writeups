# BUILDING ASSETS FIRST
FROM node:20-alpine AS assets
WORKDIR /app

COPY challenge/app/package*.json ./
RUN npm install --no-audit --no-fund
COPY challenge/app/*.config.* ./
COPY challenge/app/resources ./resources
COPY challenge/app/public   ./public
RUN npm run build

# EDITOR => ON SERVER THERE IS AN EDITOR
# FROM node:20-alpine AS editor-builder

# WORKDIR /editor
# COPY editor/frontend/package*.json ./
# RUN npm install --no-audit --no-fund
# COPY editor/frontend/ ./
# RUN npm run build

# FINAL STAGER IS PHP FOR OUR LARAVEL APP
FROM php:8.3-fpm-alpine

# System deps + nginx + supervisor
RUN apk add --no-cache caddy supervisor bash curl tzdata git icu-dev oniguruma-dev libzip-dev python3 py3-pip $PHPIZE_DEPS
RUN docker-php-ext-install -j"$(nproc)" pdo pdo_mysql bcmath intl zip opcache mbstring && apk del $PHPIZE_DEPS

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
ENV COMPOSER_ALLOW_SUPERUSER=1

# Create non-root users
RUN addgroup -S challenger \
      && adduser -S challenger -G challenger \
      && addgroup -S editor \
      && adduser -S editor -G editor -s /bin/bash \
      && addgroup editor challenger

# Add password for root
# RUN echo "root:HIDDEN_FROM_PLAYER" | chpasswd && chmod ug+s /bin/su
# RUN pip install --break-system-packages --no-cache-dir flask requests aiohttp flask-socketio flask-cors


# MAIN APP CONFIGURATION
WORKDIR /app/main_app

COPY challenge/app/composer.json challenge/app/composer.lock ./
RUN composer install --no-dev --prefer-dist --no-progress --no-interaction --no-ansi --no-scripts

COPY challenge/app .
COPY --from=assets /app/public/build /app/main_app/public/build

# COPY editor/backend /app/editor/backend
# COPY --from=editor-builder /editor/dist /app/editor/backend/static
# RUN mkdir -p /app/editor && chown -R editor:editor /app/editor && chmod -R 770 /app/editor

RUN chown -R challenger:editor /app/main_app && chmod -R g+w /app/main_app

# CONFIGURATION FOR PROXY,PHP,SUPERVISORD,ENTRYPOINT
COPY config/Caddyfile /etc/caddy/Caddyfile
COPY config/supervisord.conf /etc/supervisord.conf
COPY config/fpm.conf /usr/local/etc/php-fpm.conf

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# FLAG.TXT
COPY flag.txt /flag.txt

# PERMISSIONS
RUN mkdir -p /run/php /var/log/supervisor /var/log/php \
      && chmod 0777 /run/php \
      && touch /var/log/php/access.log /var/log/php/error.log \
      && chown -R challenger:challenger /var/log/php

RUN mkdir -p storage/logs storage/framework/cache/data storage/framework/sessions storage/framework/views bootstrap/cache \
      && chown -R challenger:challenger storage bootstrap/cache \
      && chmod -R ug+rwX storage bootstrap/cache

# FINAL TOUCHES
RUN chmod 777 -R database || true
RUN php artisan migrate --force || true
RUN php artisan db:seed --class=InitialDataSeeder --force || true

# PORT 1337
EXPOSE 1337

# APP AND HEALTHCHECK
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -fsS http://localhost:1337/ >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
