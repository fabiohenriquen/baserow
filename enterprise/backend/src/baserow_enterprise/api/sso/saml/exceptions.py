class InvalidSamlConfiguration(Exception):
    """
    This exception is raised when the SAML configuration is invalid.
    """


class InvalidSamlResponse(Exception):
    """
    This exception is raised when the SAML response is invalid.
    """


class InvalidSamlRequest(Exception):
    """
    This exception is raised when the SAML request is invalid.
    """


class SamlProviderWithSameDomainAlreadyExists(Exception):
    """
    This exception is raised when a SAML provider is created or updated with a
    domain that already exists.
    """


class InvalidSamlProviderMetadata(Exception):
    """
    This exception is raised when the metadata of a SAML provider is invalid.
    """