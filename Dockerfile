# Multi-runtime MCP Server Environment
# This image includes everything needed to run MCP servers:
# - Python 3.12 (pip, uv, pipx) - for Python-based MCP servers
# - Node.js 22.x LTS (npm, npx) - for JavaScript/TypeScript MCP servers
# - Docker CLI & Compose - for containerized MCP servers
# - Git & SSH - for repository operations
# - Build tools (gcc, g++, make) - for compiling native dependencies
# - Utilities (jq, yq, curl, wget, zip, tar) - for data processing & archives
# Based on Ubuntu 24.04 LTS for stability and compatibility
FROM ubuntu:24.04

WORKDIR /app

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python 3.11, Node.js LTS, and Docker
RUN apt-get update && apt-get install -y \
    # Core utilities
    curl \
    wget \
    git \
    ca-certificates \
    gnupg \
    lsb-release \
    software-properties-common \
    openssh-client \
    jq \
    yq \
    unzip \
    zip \
    tar \
    gzip \
    bzip2 \
    bash \
    # Python build dependencies
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    python3-pip \
    build-essential \
    gcc \
    g++ \
    make \
    libffi-dev \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libncursesw5-dev \
    xz-utils \
    tk-dev \
    libxml2-dev \
    libxmlsec1-dev \
    liblzma-dev \
    && rm -rf /var/lib/apt/lists/*

# Set Python 3.12 as default python3
RUN update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1

# Install uv (fast Python package installer) - required for MCP servers
RUN pip3 install --break-system-packages uv

# Install pipx (for isolated Python app installations)
RUN pip3 install --break-system-packages --upgrade pipx \
    && pipx ensurepath

# Install Node.js LTS (22.x) and npm
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest \
    && rm -rf /var/lib/apt/lists/*

# Install Docker CLI (latest stable)
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
    && apt-get update \
    && apt-get install -y docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN echo "=== Verifying Installations ===" \
    && python3 --version \
    && pip3 --version \
    && uv --version \
    && pipx --version \
    && node --version \
    && npm --version \
    && npx --version \
    && docker --version \
    && git --version \
    && jq --version \
    && yq --version \
    && ssh -V \
    && bash --version | head -n1 \
    && echo "=== All tools verified successfully ==="

# Install the dependencies
COPY requirements.txt .
COPY requirements-dev.txt .
RUN pip3 install --break-system-packages --upgrade --ignore-installed pip setuptools wheel \
    && pip3 install --break-system-packages --ignore-installed -r requirements.txt \
    && pip3 install --break-system-packages --ignore-installed -r requirements-dev.txt

# Copy source code
COPY src src
COPY setup.py setup.py
COPY MANIFEST.in MANIFEST.in
COPY pyproject.toml pyproject.toml

# Other files
COPY CHANGELOG.md CHANGELOG.md
COPY LICENSE.txt LICENSE.txt
COPY README.md README.md
COPY README_PYPI.md README_PYPI.md

# For ingress to work
ENV HOST=0.0.0.0
ENV FASTAPI_HOST=0.0.0.0

# Build the package
RUN python3 -m build

# Install the package
RUN pip3 install --break-system-packages .
EXPOSE 8000

# Set the entrypoint to the script
ENTRYPOINT ["python3", "src/secure_mcp_gateway/gateway.py"]
# Alternative: ENTRYPOINT ["mcp", "run", "src/secure_mcp_gateway/gateway.py"]
