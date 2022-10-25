from .exceptions import SingleSignOnFeatureNotAvailableError


def check_sso_feature_is_active_or_raise():
    """
    Checks if the single-sign-on feature is active in this instance and if not
    raises an exception.

    :raises SingleSignOnFeatureNotAvailableError: When the single-sign-on
        feature is not available.
    """

    # TODO: implement the logic to check if the single-sign-on feature is active.

    if False:
        raise SingleSignOnFeatureNotAvailableError()


def is_sso_feature_active() -> bool:
    """
    Checks if the single-sign-on feature is active in this instance.

    :return: True if the single-sign-on feature is active, otherwise False.
    """

    try:
        check_sso_feature_is_active_or_raise()
    except SingleSignOnFeatureNotAvailableError:
        return False
    return True
