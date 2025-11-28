FROM node:18

RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx supervisor mariadb-server mariadb-client bash curl && rm -rf /var/lib/apt/lists/*

# Create nginx and mysql users if they don't exist
RUN id -u nginx > /dev/null 2>&1 || useradd -r -s /bin/false nginx
RUN id -u mysql > /dev/null 2>&1 || useradd -r -s /bin/false mysql

RUN mkdir -p /run/nginx /var/log/nginx /var/lib/mysql /etc/supervisor.d /app/scripts
RUN chown -R mysql:mysql /var/lib/mysql

WORKDIR /app/bot
COPY bot/package*.json ./
RUN npm ci --only=production || npm install --production

RUN npx playwright install-deps
RUN npx playwright install chromium

COPY bot/ .

WORKDIR /app

COPY app/package*.json ./
RUN npm ci --only=production || npm install --production
RUN npm install dotenv --no-save

COPY app/ .

WORKDIR /app

COPY config/supervisord.conf /etc/supervisord.conf
COPY config/nginx.conf /etc/nginx/nginx.conf
COPY init.sh /init.sh
RUN chmod +x /init.sh

COPY scripts/generate-secrets.sh /app/scripts/generate-secrets.sh
RUN chmod +x /app/scripts/generate-secrets.sh

COPY flag.txt /flag.txt
RUN chmod +x /app/init/init_db.sh

RUN mariadb-install-db --user=mysql --datadir=/var/lib/mysql

RUN /app/scripts/generate-secrets.sh

EXPOSE 80

CMD ["/init.sh"]
