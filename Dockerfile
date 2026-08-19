# Multi-runtime MCP Server Environment
# This image includes everything needed to run MCP servers:
# - Python 3.12 (pip, uv, pipx) - for Python-based MCP servers
# - Node.js 22.x LTS (npm, npx) - for JavaScript/TypeScript MCP servers
# - Docker CLI & Compose - for containerized MCP servers (Optional, commented out for security reasons)
# - Git & SSH - for repository operations
# - Build tools (gcc, g++, make) - for compiling native dependencies
# - Utilities (jq, yq, curl, wget, zip, tar) - for data processing & archives
# Based on Ubuntu 24.04 LTS for stability and compatibility
FROM ubuntu:24.04

WORKDIR /app

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies, Python 3.11, Node.js LTS, and Docker
# The ubuntu:24.04 tag is refreshed on Canonical's release cadence, not Ubuntu's
# security cadence, so `upgrade` is required to get patched OS packages.
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
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
# Pinned so the version is visible: unpinned, this layer never rebuilds and the
# image keeps whatever uv the first build resolved, along with the Rust crates
# statically linked into that binary. Bump on uv releases.
RUN pip3 install --break-system-packages uv==0.12.5

# Install pipx (for isolated Python app installations)
RUN pip3 install --break-system-packages --upgrade pipx \
    && pipx ensurepath

# Install Node.js LTS (22.x); npm bundled with the package is recent enough
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# # NOTE: Only use if you are fine with risks of running Docker inside the container
# # Install Docker CLI (latest stable)
# RUN install -m 0755 -d /etc/apt/keyrings \
#     && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
#     && chmod a+r /etc/apt/keyrings/docker.gpg \
#     && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
#     $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \
#     && apt-get update \
#     && apt-get install -y docker-ce-cli docker-compose-plugin \
#     && rm -rf /var/lib/apt/lists/*

# Verify installations
RUN echo "=== Verifying Installations ===" \
    && python3 --version \
    && pip3 --version \
    && uv --version \
    && pipx --version \
    && node --version \
    && npm --version \
    && npx --version \
    # && docker --version \
    && git --version \
    && jq --version \
    && yq --version \
    && ssh -V \
    && bash --version | head -n1 \
    && echo "=== All tools verified successfully ==="

# Install the dependencies
COPY requirements.txt .
RUN pip3 install --break-system-packages --upgrade --ignore-installed pip setuptools wheel \
    && pip3 install --break-system-packages --ignore-installed -r requirements.txt

# Copy source code
COPY src src
COPY MANIFEST.in MANIFEST.in
COPY pyproject.toml pyproject.toml

# Other files
COPY CHANGELOG.md CHANGELOG.md
COPY LICENSE LICENSE
COPY README.md README.md
COPY README_PYPI.md README_PYPI.md

# For ingress to work
ENV HOST=0.0.0.0
ENV FASTAPI_HOST=0.0.0.0

# Install the package (PEP 517 build via setuptools.build_meta)
RUN pip3 install --break-system-packages .

# Sits after the COPY steps, which any source change invalidates, so releases
# pick up OS patches published since the cached upgrade layer above was built.
#
# The apt copies of pip and wheel are dropped here: their fixes ship only in
# Ubuntu Pro (ESM), and nothing uses them, since the pip installs above put
# newer ones in /usr/local. python3-pip-whl is deliberately left installed -
# python3.12-venv depends on it, and force-removing it leaves apt unable to
# install anything at all.
RUN apt-get update && apt-get upgrade -y \
    && apt-get purge -y python3-pip python3-wheel \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Replace the pip wheel that python3-pip-whl stages for `python3 -m venv` to
# bootstrap from. Ubuntu 24.04 stages pip 24.0, which carries vendored copies of
# urllib3 1.26.17 and requests 2.31.0 - the actual subjects of CVE-2025-66471,
# CVE-2025-66418 and CVE-2024-35195. Current pip vendors urllib3 >= 2.7 and
# requests >= 2.34, so this removes that code from the image and hands new venvs
# a current pip instead of a two-year-old one. ensurepip resolves this directory
# by scanning it (_find_packages), so the version in the filename is picked up
# with no further wiring.
#
# Inspector reads dpkg metadata rather than file contents, so it will keep
# reporting those three CVEs against python3-pip-whl 24.0 regardless. Only
# Ubuntu Pro (ESM) clears the finding itself; this clears the vulnerability.
#
# Must stay after the upgrade above, or an upgrade of python3-pip-whl puts the
# old wheel back. The venv probe is the regression test: if a future pip layout
# stops satisfying ensurepip, the build fails here rather than shipping an image
# where MCP servers cannot create virtualenvs.
RUN pip3 download --no-deps --quiet --dest /tmp/pipwhl pip \
    && rm -f /usr/share/python-wheels/pip-*.whl \
    && cp /tmp/pipwhl/pip-*.whl /usr/share/python-wheels/ \
    && rm -rf /tmp/pipwhl \
    && python3 -m venv /tmp/venv-probe \
    && /tmp/venv-probe/bin/pip --version \
    && rm -rf /tmp/venv-probe

EXPOSE 8000

# Set the entrypoint to the script
ENTRYPOINT ["python3", "src/secure_mcp_gateway/gateway.py"]
# Alternative: ENTRYPOINT ["mcp", "run", "src/secure_mcp_gateway/gateway.py"]

