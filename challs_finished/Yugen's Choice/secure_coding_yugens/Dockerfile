# Editor Assets for Frontend
# FROM node:20-alpine AS editor-builder
# 
# WORKDIR /editor
# COPY editor/frontend/package*.json ./
# RUN npm install --no-audit --no-fund
# COPY editor/frontend/ ./
# RUN npm run build


# Final image is a python image to host both endpoints
FROM python:3.15-rc-alpine AS final-builder

# ADD USERS TO MANAGE PERMISSIONS
RUN addgroup -S challenger && adduser -S challenger -G challenger \
    && addgroup -S editor && adduser -S editor -G editor -s /bin/bash \
    && addgroup editor challenger

# ROOT'S PASSWORD
RUN echo "root:HIDDEN_FROM_PLAYER" | chpasswd && chmod ug+s /bin/su


# First align and copy the editor assets and the backend
RUN mkdir /app && chown editor:challenger /app
# COPY --chown=editor:editor --chmod=770 --from=editor-builder /editor/dist /app/editor/backend/static
# COPY --chown=editor:editor --chmod=770 editor/backend /app/editor/backend

# Install packages
# RUN pip install -r /app/editor/backend/requirements.txt
RUN apk add --no-cache caddy supervisor bash tzdata git icu-dev oniguruma-dev libzip-dev redis curl
# Build main app
WORKDIR /app/main_app

COPY challenge/app ./
RUN pip install -r /app/main_app/requirements.txt
ENV PYTHONUNBUFFERED=1

# Necessary log directories and permissions
RUN mkdir /var/log/supervisor /var/log/frontend /var/log/backend /var/log/caddy \
    && chmod 776 -R /var/log

# RUN chown -R editor:editor /app/editor && chmod -R 770 /app/editor
RUN chown -R editor:challenger /app/main_app && chmod -R 775 /app/main_app


# COPY CONFIG FILES
COPY --chown=root:root --chmod=770 config/supervisord.conf /etc/supervisord.conf
COPY --chown=root:root --chmod=770 config/Caddyfile /etc/caddy/Caddyfile

COPY --chown=root:root --chmod=770 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chown=root:editor --chmod=640 flag.txt /flag.txt

# INITIALIZE AND RUN THE APP
EXPOSE 1337
CMD ["/usr/local/bin/entrypoint.sh"]