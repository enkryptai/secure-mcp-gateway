FROM python:3.11-alpine

WORKDIR /app

# Install the dependencies
COPY requirements.txt .
COPY requirements-dev.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt && pip install -r requirements-dev.txt

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

# Build the package
RUN python -m build

# Install the package
RUN pip install .

EXPOSE 8000

# Set the entrypoint to the script
# ENTRYPOINT ["python", "src/secure_mcp_gateway/gateway.py"]
ENTRYPOINT ["mcp", "run", "src/secure_mcp_gateway/gateway.py"]
