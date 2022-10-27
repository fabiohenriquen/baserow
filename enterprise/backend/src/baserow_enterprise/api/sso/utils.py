from enum import Enum
from typing import Optional
from urllib.parse import urlencode, urlparse

from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.http import HttpResponse
from django.shortcuts import redirect

from baserow.core.user.utils import generate_session_tokens_for_user


# please keep this in sync with baserow_enterprise/locales/en.json
class SsoErrorCode(Enum):
    FEATURE_NOT_ACTIVE = "errorSsoFeatureNotActive"
    INVALID_SAML_REQUEST = "errorInvalidSamlRequest"
    INVALID_SAML_RESPONSE = "errorInvalidSamlResponse"
    ERROR_USER_DEACTIVATED = "errorUserDeactivated"


def redirect_to_sign_in_error_page(
    error_code: Optional[SsoErrorCode] = None,
) -> HttpResponse:
    """
    Redirects the user to the error page in the frontend providing a message as
    query parameter if provided.

    :param error_message: The message that should be shown to the user.
    :return: The redirect response to the frontend error page with the error
        message encoded as query param.
    """

    frontend_error_page_url = settings.PUBLIC_WEB_FRONTEND_URL + "/login/error"
    if error_code:
        error_frontend_code = error_code.value
        frontend_error_page_url += "?" + urlencode({"error": error_frontend_code})
    return redirect(frontend_error_page_url)


def get_absolute_frontend_url_or_default(
    requested_original_url: Optional[str] = None,
) -> str:
    """
    Returns a valid absolute frontend url based on the original url requested
    before the redirection to the login. If the original url is relative, it
    will be prefixed with the frontend hostname to make the IdP redirection
    work. If the original url is external to Baserow, the default public
    frontend url will be returned instead.

    :param requested_original_url: The url to which the user should be
        redirected after a successful login.
    :return: The url with the token as a query parameter.
    """

    parsed_url = urlparse(requested_original_url)
    default_frontend_url = urlparse(settings.PUBLIC_WEB_FRONTEND_URL)

    if parsed_url.hostname is None:
        parsed_url = default_frontend_url._replace(path=parsed_url.path)
    if parsed_url.hostname != default_frontend_url.hostname:
        parsed_url = default_frontend_url

    return str(parsed_url.geturl())


def urlencode_user_token_for_frontend_url(frontend_url: str, user: AbstractUser) -> str:
    """
    Adds the token as a query parameter to the provided frontend url.
    Please ensure to call the get_url_for_frontend_page_if_valid_or_default()
    method before calling this method, so to be sure to encode the refresh token
    in a valid Baserow frontend url.

    :param frontend_url: The url to which the user should be redirected
        after a successful login.
    :param user: The user that sign in with an external provider and is going to
        start a new session in Baserow.
    :return: The url with the token as a query parameter.
    """

    parsed_url = urlparse(frontend_url)
    user_tokens = generate_session_tokens_for_user(user, include_refresh_token=True)
    return parsed_url._replace(query="token=" + user_tokens["refresh_token"]).geturl()


def redirect_user_on_success(
    user: AbstractUser, requested_original_url: Optional[str] = None
) -> HttpResponse:
    """
    Ensure that the requested original url is valid or take the frontend default
    url. It adds the JWT token as query parameter to the url so that the user
    can start a new session.

    :param user: The user that sign in with an external provider and is going to
        start a new session in Baserow.
    :param requested_original_url: The url to which the user should be
        redirected after a successful login.
    :return: The redrect HTTP response to the url with the token as a query parameter.
    """

    valid_frontend_url = get_absolute_frontend_url_or_default(requested_original_url)
    redirect_url = urlencode_user_token_for_frontend_url(valid_frontend_url, user)
    return redirect(redirect_url)
