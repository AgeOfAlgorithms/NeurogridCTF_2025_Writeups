# DOCKERFILE FOR SHUGO NO MICHI SECURE CODING CHALLENGE
# Editor Assets for Frontend
# FROM node:20-alpine AS editor-builder
# 
# WORKDIR /editor
# COPY editor/frontend/package*.json ./
# RUN npm install --no-audit --no-fund
# COPY editor/frontend/ ./
# RUN npm run build


# The vulnerable application consists of various apps
FROM ruby:3.5-rc-alpine AS main_app


# INSTALL PACKAGES
RUN apk add --no-cache bash tzdata git curl ca-certificates \
    build-base cmake make g++ \
    postgresql16 postgresql16-client postgresql16-contrib \
    postgresql-dev postgresql-libs \
    supervisor caddy \
    python3 py3-pip \
    icu-dev oniguruma-dev libzip-dev zlib-dev openssl-dev readline-dev yaml-dev libffi-dev \
    libxml2-dev libxslt-dev


# ADD USERS TO MANAGE PERMISSIONS
RUN addgroup -S challenger && adduser -S challenger -G challenger \
    && addgroup -S editor && adduser -S editor -G editor -s /bin/bash \
    && addgroup editor challenger

# ROOT'S PASSWORD
RUN echo "root:HIDDEN_FROM_PLAYER" | chpasswd && chmod ug+s /bin/su


##### FORMULATE APP STRUCTURES => 4 CORE APPS, 1 EDITOR
RUN bash -lc 'mkdir -p /app/core_app /app/core_app/{web_app,database,logic_tracker,data_parser}'

#### SCENARIO USAGE
COPY challenge/scenario.pdf /app/core_app/scenario.pdf


## RUBY APP : WEB APPLICATION
WORKDIR /app/core_app/web_app

COPY challenge/app/web_app .

RUN gem install bundler -v 2.7.1 --no-document && bundle config set without 'test' && bundle install --jobs 4 --retry 3
RUN bundle exec rails tailwindcss:build || true


## C++ APP : DATA PARSER
WORKDIR /app/core_app/data_parser

COPY challenge/app/data_parser .

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --config Release && mkdir -p data


## PYTHON APP : LOGIC TRACKER
WORKDIR /app/core_app/logic_tracker

COPY challenge/app/logic_tracker .

RUN python3 -m pip install --upgrade setuptools wheel --break-system-packages && \
    python3 -m pip install --no-cache-dir -r requirements.txt --break-system-packages


# POSTGRES : DATABASE
RUN mkdir -p /var/lib/postgresql/data \
 && chown -R postgres:postgres /var/lib/postgresql \
 && chmod 0700 /var/lib/postgresql/data

RUN install -d -m 0775 -o postgres -g postgres /run/postgresql
COPY challenge/app/database/schema.sql /app/core_app/database/schema.sql

## EDITOR APP
# COPY --chown=editor:editor --chmod=770 --from=editor-builder /editor/dist /app/editor/backend/static
# COPY --chown=editor:editor --chmod=770 editor/backend /app/editor/backend

# RUN pip install -r /app/editor/backend/requirements.txt --break-system-packages

# CONFIGURATION
RUN mkdir -p /etc/supervisor/conf.d /etc/caddy /var/log/supervisor

COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY config/Caddyfile /etc/caddy/Caddyfile
COPY entrypoint.sh /usr/bin/entrypoint.sh
RUN chmod +x /usr/bin/entrypoint.sh

COPY flag.txt /flag.txt

# EXPOSE 1 MAIN PORT, 1337
WORKDIR /app/core_app
RUN chown -R editor:challenger /app/core_app && chmod -R 775 /app/core_app
RUN chown -R root:postgres /app/core_app/database && chmod -R 775 /app/core_app/database


EXPOSE 1337

# RUN THE CORE ENTRY POINT
CMD ["/usr/bin/entrypoint.sh"]
