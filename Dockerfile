FROM python:3.11-slim

# Install system dependencies including iptables and wireguard tools
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    wireguard-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

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

# Create directory for rules file
RUN mkdir -p /app/data

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

# Default credentials (should be overridden in production)
ENV ADMIN_USER=admin
ENV ADMIN_PASS=password

# Expose port
EXPOSE 8080

# Make sure the app has permissions to run iptables
# Note: The container needs to be run with --privileged or --cap-add=NET_ADMIN
USER root

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/login || exit 1

# Start the application
CMD ["python", "app.py"]