from baserow_premium.license.registries import LicenseType

from baserow_enterprise.license.features import SSO


class EnterpriseLicenseType(LicenseType):
    type = "enterprise"
    order = 5
    features = [SSO]
