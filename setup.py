from setuptools import setup, find_packages

# Read version and dependencies directly from version.py and dependencies.py
# Thanks to: https://stackoverflow.com/questions/458550/standard-way-to-embed-version-into-python-package

try:
    with open("src/secure_mcp_gateway/version.py", encoding="utf-8") as f:
        exec(f.read())
except FileNotFoundError:
    print("version.py NOT FOUND in setup.py. Using fallback version 1.0.0")
    __version__ = "1.0.0"  # fallback version

try:
    with open("src/secure_mcp_gateway/dependencies.py", encoding="utf-8") as f:
        exec(f.read())
except FileNotFoundError:
    print("dependencies.py NOT FOUND in setup.py. Using fallback empty dependencies")
    __dependencies__ = []  # fallback empty dependencies

print("VERSION got in setup.py: ", __version__)
print("DEPENDENCIES got in setup.py: ", __dependencies__)
print("PACKAGES FOUND:", find_packages(where="src"))

try:
    with open("README_PYPI.md", encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "See https://github.com/enkryptai/secure-mcp-gateway"

setup(
    name="secure-mcp-gateway",
    version=__version__,
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
    install_requires=__dependencies__,
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
