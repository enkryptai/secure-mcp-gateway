FROM python:3.11-alpine

WORKDIR /app

# Install build dependencies required for psutil and other packages
RUN apk add --no-cache --virtual .build-deps \
    gcc \
    python3-dev \
    musl-dev \
    linux-headers \
    && apk add --no-cache \
    libffi-dev

# Install the dependencies
COPY requirements.txt .
COPY requirements-dev.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt && pip install -r requirements-dev.txt && apk del .build-deps

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
RUN python -m build

# Install the package
RUN pip install .

EXPOSE 8000

# Set the entrypoint to the script
# ENTRYPOINT ["python", "src/secure_mcp_gateway/gateway.py"]
ENTRYPOINT ["mcp", "run", "src/secure_mcp_gateway/gateway.py"]
