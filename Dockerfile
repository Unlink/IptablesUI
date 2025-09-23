FROM python:3.11-slim

# Install system dependencies including iptables, wireguard tools, and S6 overlay requirements
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    wireguard-tools \
    curl \
    wget \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install S6 overlay
ARG S6_OVERLAY_VERSION=3.1.6.2
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz \
    && rm /tmp/s6-overlay-*.tar.xz

# Set working directory
WORKDIR /app

# Copy requirements first for better Docker layer caching
COPY requirements.txt .

# Upgrade pip and setuptools to latest secure versions
RUN pip install --no-cache-dir --upgrade pip setuptools>=78.1.1

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create directory for rules file and WireGuard config
RUN mkdir -p /app/data /etc/wireguard && chmod 700 /etc/wireguard

# Create S6 service directories
RUN mkdir -p /etc/s6-overlay/s6-rc.d/iptablesui/dependencies.d \
    && mkdir -p /etc/s6-overlay/s6-rc.d/wireguard-setup/dependencies.d \
    && mkdir -p /etc/s6-overlay/s6-rc.d/networking-setup/dependencies.d \
    && mkdir -p /etc/s6-overlay/s6-rc.d/user/contents.d

# Create networking setup service (runs first)
RUN echo "oneshot" > /etc/s6-overlay/s6-rc.d/networking-setup/type
COPY s6-services/networking-setup /etc/s6-overlay/s6-rc.d/networking-setup/up
RUN chmod +x /etc/s6-overlay/s6-rc.d/networking-setup/up

# Create WireGuard setup service (runs after networking)
RUN echo "oneshot" > /etc/s6-overlay/s6-rc.d/wireguard-setup/type \
    && echo "networking-setup" > /etc/s6-overlay/s6-rc.d/wireguard-setup/dependencies.d/networking-setup
COPY s6-services/wireguard-setup /etc/s6-overlay/s6-rc.d/wireguard-setup/up
RUN chmod +x /etc/s6-overlay/s6-rc.d/wireguard-setup/up

# Create IptablesUI service (long-running Flask app)
RUN echo "longrun" > /etc/s6-overlay/s6-rc.d/iptablesui/type \
    && echo "wireguard-setup" > /etc/s6-overlay/s6-rc.d/iptablesui/dependencies.d/wireguard-setup
COPY s6-services/iptablesui-run /etc/s6-overlay/s6-rc.d/iptablesui/run
COPY s6-services/iptablesui-finish /etc/s6-overlay/s6-rc.d/iptablesui/finish
RUN chmod +x /etc/s6-overlay/s6-rc.d/iptablesui/run \
    && chmod +x /etc/s6-overlay/s6-rc.d/iptablesui/finish

# Enable services in user bundle
RUN echo "iptablesui" > /etc/s6-overlay/s6-rc.d/user/contents.d/iptablesui \
    && echo "wireguard-setup" > /etc/s6-overlay/s6-rc.d/user/contents.d/wireguard-setup \
    && echo "networking-setup" > /etc/s6-overlay/s6-rc.d/user/contents.d/networking-setup

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1
ENV S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0

# Default credentials (should be overridden in production)
ENV ADMIN_USER=admin
ENV ADMIN_PASS=password

# Expose ports
EXPOSE 8080 51820/udp

# Make sure the app has permissions to run iptables and wireguard
USER root

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/login || exit 1

# S6 overlay entrypoint
ENTRYPOINT ["/init"]