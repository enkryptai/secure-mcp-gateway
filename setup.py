from setuptools import setup, find_packages
# from src.secure_mcp_gateway import __version__, __dependencies__

print("PACKAGES FOUND:", find_packages(where="src"))

try:
    with open("README_PYPI.md", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "See https://github.com/enkryptai/secure-mcp-gateway"

setup(
    name="secure-mcp-gateway",
    # NOTE: Also change version in __init__.py, pyproject.toml, and setup.py
    version="1.0.0",
    # version=__version__,
    description="Enkrypt Secure MCP Gateway",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Enkrypt AI Team",
    author_email="support@enkryptai.com",
    url="https://github.com/enkryptai/secure-mcp-gateway",
    python_requires=">=3.8",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    # NOTE: Also change these in dependencies.py, pyproject.toml, and setup.py
    install_requires=[
        "flask>=2.0.0",
        "flask-cors>=3.0.0",
        "redis>=4.0.0",
        "requests>=2.26.0",
        "aiohttp>=3.8.0",
        "python-json-logger>=2.0.0",
        "python-dateutil>=2.8.2",
        "cryptography>=3.4.0",
        "pyjwt>=2.0.0",
        "asyncio>=3.4.3",
        "mcp[cli]",
    ],
    # install_requires=__dependencies__,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    entry_points={
        "console_scripts": [
            "secure-mcp-gateway = secure_mcp_gateway.cli:main",
        ],
    },
)
