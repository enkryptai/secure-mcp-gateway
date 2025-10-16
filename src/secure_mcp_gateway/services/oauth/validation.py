"""OAuth configuration validation utilities."""

from typing import Dict, List, Optional, Tuple

from secure_mcp_gateway.services.oauth.models import (
    OAuthConfig,
    OAuthGrantType,
    OAuthVersion,
)
from secure_mcp_gateway.utils import logger


class OAuthConfigValidator:
    """Validates OAuth configurations for MCP servers."""

    @staticmethod
    def validate_config(oauth_config_data: Dict) -> Tuple[bool, List[str]]:
        """
        Validate OAuth configuration dictionary.

        Args:
            oauth_config_data: OAuth configuration dictionary

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not isinstance(oauth_config_data, dict):
            errors.append("OAuth config must be a dictionary")
            return False, errors

        # Check if enabled
        if not oauth_config_data.get("enabled", False):
            return True, []  # Disabled config is valid

        # Check required fields
        required_fields = {
            "OAUTH_TOKEN_URL": "Token URL is required",
            "OAUTH_CLIENT_ID": "Client ID is required for client_credentials grant",
            "OAUTH_CLIENT_SECRET": "Client Secret is required for client_credentials grant",
        }

        grant_type = oauth_config_data.get("OAUTH_GRANT_TYPE", "client_credentials")
        version = oauth_config_data.get("OAUTH_VERSION", "2.0")

        # Token URL is always required
        if not oauth_config_data.get("OAUTH_TOKEN_URL"):
            errors.append("OAUTH_TOKEN_URL is required")

        # Client credentials required for client_credentials grant
        if grant_type == "client_credentials":
            if not oauth_config_data.get("OAUTH_CLIENT_ID"):
                errors.append(
                    "OAUTH_CLIENT_ID is required for client_credentials grant"
                )
            if not oauth_config_data.get("OAUTH_CLIENT_SECRET"):
                errors.append(
                    "OAUTH_CLIENT_SECRET is required for client_credentials grant"
                )

        # OAuth 2.1 specific validations
        if "2.1" in version:
            token_url = oauth_config_data.get("OAUTH_TOKEN_URL", "")
            if token_url and not token_url.startswith("https://"):
                errors.append("OAuth 2.1 requires HTTPS for token URL")

        # Validate version
        valid_versions = ["2.0", "2.1"]
        if version not in valid_versions:
            errors.append(
                f"Invalid OAuth version: {version}. Must be one of {valid_versions}"
            )

        # Validate grant type
        valid_grant_types = ["client_credentials", "authorization_code"]
        if grant_type not in valid_grant_types:
            errors.append(
                f"Invalid grant type: {grant_type}. Must be one of {valid_grant_types}"
            )

        return len(errors) == 0, errors

    @staticmethod
    def validate_oauth_config_object(
        oauth_config: OAuthConfig,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate OAuthConfig object.

        Args:
            oauth_config: OAuthConfig instance

        Returns:
            Tuple of (is_valid, error_message)
        """
        return oauth_config.validate()

    @staticmethod
    def validate_server_oauth_config(server_entry: Dict) -> Tuple[bool, List[str]]:
        """
        Validate OAuth configuration in server entry.

        Args:
            server_entry: Server configuration entry

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        oauth_config_data = server_entry.get("oauth_config")

        if not oauth_config_data:
            return True, []  # No OAuth config is valid

        return OAuthConfigValidator.validate_config(oauth_config_data)

    @staticmethod
    def get_oauth_config_summary(oauth_config_data: Dict) -> str:
        """
        Get human-readable summary of OAuth configuration.

        Args:
            oauth_config_data: OAuth configuration dictionary

        Returns:
            Summary string
        """
        if not oauth_config_data:
            return "OAuth: Not configured"

        enabled = oauth_config_data.get("enabled", False)
        if not enabled:
            return "OAuth: Disabled"

        version = oauth_config_data.get("OAUTH_VERSION", "2.0")
        grant_type = oauth_config_data.get("OAUTH_GRANT_TYPE", "client_credentials")
        token_url = oauth_config_data.get("OAUTH_TOKEN_URL", "")
        client_id = oauth_config_data.get("OAUTH_CLIENT_ID", "")

        # Mask client ID
        masked_client_id = f"***{client_id[-4:]}" if len(client_id) > 4 else "****"

        summary_parts = [
            f"OAuth {version}",
            f"Grant: {grant_type}",
            f"Client ID: {masked_client_id}",
            f"Token URL: {token_url}",
        ]

        # Add optional fields
        if oauth_config_data.get("OAUTH_AUDIENCE"):
            summary_parts.append(f"Audience: {oauth_config_data['OAUTH_AUDIENCE']}")

        if oauth_config_data.get("OAUTH_SCOPE"):
            summary_parts.append(f"Scope: {oauth_config_data['OAUTH_SCOPE']}")

        return " | ".join(summary_parts)

    @staticmethod
    def check_oauth_2_1_compliance(oauth_config_data: Dict) -> Tuple[bool, List[str]]:
        """
        Check if OAuth configuration is OAuth 2.1 compliant.

        Args:
            oauth_config_data: OAuth configuration dictionary

        Returns:
            Tuple of (is_compliant, list_of_warnings)
        """
        warnings = []

        version = oauth_config_data.get("OAUTH_VERSION", "2.0")
        if version != "2.1":
            return True, []  # Only check 2.1 configs

        # Check HTTPS enforcement
        token_url = oauth_config_data.get("OAUTH_TOKEN_URL", "")
        if not token_url.startswith("https://"):
            warnings.append("OAuth 2.1 requires HTTPS for all endpoints")

        # Check authentication method
        use_basic_auth = oauth_config_data.get("OAUTH_USE_BASIC_AUTH", True)
        if not use_basic_auth:
            warnings.append(
                "OAuth 2.1 recommends client_secret_basic over client_secret_post"
            )

        # Check token placement
        token_in_header_only = oauth_config_data.get("OAUTH_TOKEN_IN_HEADER_ONLY", True)
        if not token_in_header_only:
            warnings.append("OAuth 2.1 prohibits tokens in URI query parameters")

        # Check PKCE for authorization code
        grant_type = oauth_config_data.get("OAUTH_GRANT_TYPE", "client_credentials")
        if grant_type == "authorization_code":
            use_pkce = oauth_config_data.get("OAUTH_USE_PKCE", False)
            if not use_pkce:
                warnings.append("OAuth 2.1 requires PKCE for authorization code flow")

        is_compliant = len(warnings) == 0
        return is_compliant, warnings


def validate_oauth_config(
    oauth_config_data: Optional[Dict],
) -> Tuple[bool, List[str]]:
    """
    Convenience function to validate OAuth configuration.

    Args:
        oauth_config_data: OAuth configuration dictionary

    Returns:
        Tuple of (is_valid, list_of_errors)
    """
    if not oauth_config_data:
        return True, []

    validator = OAuthConfigValidator()
    return validator.validate_config(oauth_config_data)


def check_oauth_compliance(
    oauth_config_data: Optional[Dict],
) -> Tuple[bool, List[str]]:
    """
    Check OAuth 2.1 compliance of configuration.

    Args:
        oauth_config_data: OAuth configuration dictionary

    Returns:
        Tuple of (is_compliant, list_of_warnings)
    """
    if not oauth_config_data:
        return True, []

    validator = OAuthConfigValidator()
    return validator.check_oauth_2_1_compliance(oauth_config_data)
