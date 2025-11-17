"""
SAML 2.0 authentication provider for enterprise SSO.

Integrates with enterprise identity providers like:
- Okta
- Azure AD
- OneLogin
- Google Workspace
- Custom SAML 2.0 providers
"""

from typing import Dict, Optional
from uuid import UUID

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from enterprise.models.sso import SSOConfiguration


class SAMLAuthProvider:
    """
    SAML 2.0 authentication provider.

    Handles:
    - SAML authentication requests
    - Assertion Consumer Service (ACS) responses
    - User attribute mapping
    - Auto-provisioning
    """

    def __init__(self, sso_config: SSOConfiguration):
        """
        Initialize SAML provider with organization's SSO configuration.

        Args:
            sso_config: SSO configuration from database
        """
        if not sso_config.is_saml:
            raise ValueError(f"SSO configuration is not SAML (type: {sso_config.provider_type})")

        self.sso_config = sso_config
        self.settings = self._build_saml_settings()

    def _build_saml_settings(self) -> Dict:
        """
        Build SAML settings dict for python3-saml library.

        Returns:
            SAML settings dictionary
        """
        return {
            "strict": True,
            "debug": False,
            "sp": {
                "entityId": f"https://app.faultmaven.ai/saml/metadata/{self.sso_config.organization_id}",
                "assertionConsumerService": {
                    "url": f"https://app.faultmaven.ai/saml/acs/{self.sso_config.organization_id}",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": f"https://app.faultmaven.ai/saml/sls/{self.sso_config.organization_id}",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": self.sso_config.saml_name_id_format or "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "x509cert": "",  # SP certificate (optional for FaultMaven)
                "privateKey": ""  # SP private key (optional for FaultMaven)
            },
            "idp": {
                "entityId": self.sso_config.saml_entity_id,
                "singleSignOnService": {
                    "url": self.sso_config.saml_sso_url,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": self.sso_config.saml_slo_url or "",
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": self.sso_config.saml_x509_cert
            }
        }

    def get_login_url(self, request_data: Dict) -> str:
        """
        Generate SAML login URL (redirect to IdP).

        Args:
            request_data: Request context dict with 'http_host', 'script_name', etc.

        Returns:
            SAML SSO redirect URL
        """
        auth = OneLogin_Saml2_Auth(request_data, self.settings)
        return auth.login()

    def process_response(self, request_data: Dict) -> Dict:
        """
        Process SAML response from IdP (Assertion Consumer Service).

        Args:
            request_data: Request context with SAML response

        Returns:
            Dict with user attributes from SAML assertion

        Raises:
            Exception: If SAML response is invalid
        """
        auth = OneLogin_Saml2_Auth(request_data, self.settings)
        auth.process_response()

        errors = auth.get_errors()
        if errors:
            error_reason = auth.get_last_error_reason()
            raise Exception(f"SAML authentication failed: {error_reason}")

        if not auth.is_authenticated():
            raise Exception("SAML authentication failed: User not authenticated")

        # Extract user attributes from SAML assertion
        attributes = auth.get_attributes()
        name_id = auth.get_nameid()

        # Map SAML attributes to user fields using configuration
        user_data = self._map_attributes(attributes, name_id)

        return user_data

    def _map_attributes(self, saml_attributes: Dict, name_id: str) -> Dict:
        """
        Map SAML attributes to user fields.

        Args:
            saml_attributes: Attributes from SAML assertion
            name_id: SAML NameID (typically email)

        Returns:
            Mapped user data dict
        """
        # Default attribute mapping
        default_mapping = {
            "email": "email",
            "full_name": "displayName",
            "first_name": "firstName",
            "last_name": "lastName"
        }

        # Use custom mapping if configured
        mapping = self.sso_config.attribute_mapping or default_mapping

        user_data = {
            "sso_subject_id": name_id,
            "sso_provider": "saml",
            "organization_id": str(self.sso_config.organization_id)
        }

        # Map each field
        for user_field, saml_field in mapping.items():
            if saml_field in saml_attributes:
                # SAML attributes are typically lists
                value = saml_attributes[saml_field]
                if isinstance(value, list) and len(value) > 0:
                    user_data[user_field] = value[0]
                else:
                    user_data[user_field] = value

        # Fallback: use NameID as email if not in attributes
        if "email" not in user_data:
            user_data["email"] = name_id

        # Generate full_name from first/last if not provided
        if "full_name" not in user_data:
            first = user_data.get("first_name", "")
            last = user_data.get("last_name", "")
            if first or last:
                user_data["full_name"] = f"{first} {last}".strip()
            else:
                user_data["full_name"] = user_data["email"].split("@")[0]

        return user_data

    def get_metadata(self) -> str:
        """
        Generate SAML Service Provider metadata XML.

        Returns:
            SAML metadata XML string
        """
        settings = OneLogin_Saml2_Settings(self.settings)
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if errors:
            raise Exception(f"Invalid SAML metadata: {errors}")

        return metadata

    def get_logout_url(self, request_data: Dict, name_id: Optional[str] = None) -> str:
        """
        Generate SAML Single Logout (SLO) URL.

        Args:
            request_data: Request context
            name_id: User's SAML NameID

        Returns:
            SAML SLO redirect URL
        """
        auth = OneLogin_Saml2_Auth(request_data, self.settings)
        return auth.logout(name_id=name_id)
