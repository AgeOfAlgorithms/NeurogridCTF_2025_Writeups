FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    redis-server \
    supervisor \
    curl \
    gcc \
    nodejs \
    npm \
    nginx \
    && rm -rf /var/lib/apt/lists/* \
    && getent group nginx || groupadd -r nginx \
    && getent passwd nginx || useradd -r -g nginx -s /bin/false -d /var/cache/nginx nginx

# Create users for each service
RUN groupadd -r appgroup && \
    useradd -r -g appgroup -d /app -s /bin/bash flaskuser && \
    useradd -r -g appgroup -d /var/lib/redis -s /bin/false redisuser && \
    useradd -r -g appgroup -d /app -s /bin/bash celeryuser

# Install Python dependencies
COPY requirements.txt .
RUN pip install -r requirements.txt

WORKDIR /app

# Copy application files
COPY . /app
RUN rm ./read_flag.c
RUN rm ./docker-compose.yml
RUN rm ./Dockerfile

# Build React app
WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json* ./
RUN npm install --legacy-peer-deps
COPY ui/ ./
# Create a minimal worker-configuration.d.ts file to fix TypeScript build
RUN echo 'declare interface Env {}' > worker-configuration.d.ts
# Build only the React app, skip worker build
RUN npx tsc -p tsconfig.app.json && npx vite build

WORKDIR /app

# Create cache directory and set permissions
RUN mkdir -p /app/cache && \
    mkdir -p /app/uploads && \
    mkdir -p /var/lib/redis && \
    mkdir -p /var/log/nginx && \
    touch /logs && \
    chown -R flaskuser:appgroup /app && \
    chown -R celeryuser:appgroup /app/cache && \
    chown -R flaskuser:appgroup /app/uploads && \
    chown -R redisuser:appgroup /var/lib/redis && \
    chmod 755 /app/cache && \
    chmod 755 /app/uploads && \
    chmod 755 /var/lib/redis && \
    chmod 644 /logs

# Set nginx log permissions
RUN chown -R nginx:nginx /var/log/nginx && \
    chown nginx:nginx /logs

# Configure nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Configure supervisor
COPY supervisord.conf /etc/supervisor/conf.d/

# Compile setuid binary and set up flag
COPY read_flag.c /tmp/read_flag.c
RUN gcc -o /usr/local/bin/read_flag /tmp/read_flag.c && \
    chmod 4755 /usr/local/bin/read_flag && \
    rm /tmp/read_flag.c

# Copy flag to root directory
RUN mv ./flag.txt /root/flag.txt && \
    chmod 600 /root/flag.txt

# Expose port
EXPOSE 80

# Start all services
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]