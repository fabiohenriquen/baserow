import json

from django.shortcuts import reverse
from django.test.utils import override_settings

import pytest
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_204_NO_CONTENT,
    HTTP_400_BAD_REQUEST,
    HTTP_402_PAYMENT_REQUIRED,
    HTTP_403_FORBIDDEN,
    HTTP_404_NOT_FOUND,
)

from baserow_enterprise.sso.saml.auth_provider_types import SamlAuthProviderType
from baserow_enterprise.sso.saml.models import SamlAuthProviderModel


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_admin_cannot_create_saml_provider_without_an_enterprise_license(
    api_client, data_fixture, enterprise_data_fixture
):

    # create a valid SAML provider
    domain = "test.it"
    metadata = enterprise_data_fixture.get_test_saml_idp_metadata()

    _, unauthorized_token = data_fixture.create_user_and_token(is_staff=True)

    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {"type": SamlAuthProviderType.type, "domain": domain, "metadata": metadata},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_402_PAYMENT_REQUIRED


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_create_saml_provider(api_client, data_fixture, enterprise_data_fixture):

    # create a valid SAML provider
    domain = "test.it"
    metadata = enterprise_data_fixture.get_test_saml_idp_metadata()

    _, token = enterprise_data_fixture.create_enterprise_admin_user_and_token()
    _, unauthorized_token = data_fixture.create_user_and_token()

    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {"type": SamlAuthProviderType.type, "domain": domain, "metadata": metadata},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_403_FORBIDDEN

    # cannot create a SAML provider with an invalid domain or metadata
    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {
            "type": SamlAuthProviderType.type,
            "domain": "invalid_domain_name",
            "metadata": metadata,
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_REQUEST_BODY_VALIDATION"
    assert json.dumps(response_json["detail"]) == json.dumps(
        {
            "domain": [
                {
                    "error": "The domain value is not a valid domain name.",
                    "code": "invalid",
                }
            ]
        }
    )
    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {
            "type": SamlAuthProviderType.type,
            "domain": "domain2.it",
            "metadata": "invalid_metadata",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_REQUEST_BODY_VALIDATION"
    assert json.dumps(response_json["detail"]) == json.dumps(
        {
            "metadata": [
                {
                    "error": "The metadata is not valid according to the XML schema.",
                    "code": "invalid",
                }
            ]
        }
    )

    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {"type": SamlAuthProviderType.type, "domain": domain, "metadata": metadata},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK
    assert response_json["id"] is not None
    assert response_json["type"] == SamlAuthProviderType.type
    assert response_json["domain"] == domain
    assert response_json["metadata"] == metadata
    assert response_json["is_verified"] is False
    assert response_json["enabled"] is True

    # cannot create another SAML provider for the same domain
    response = api_client.post(
        reverse("api:enterprise:admin:auth_provider:list"),
        {"type": SamlAuthProviderType.type, "domain": domain, "metadata": metadata},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_SAML_PROVIDER_FOR_DOMAIN_ALREADY_EXISTS"

    assert SamlAuthProviderModel.objects.count() == 1

    # ensure the login option is now listed in the login options
    response = api_client.get(
        reverse("api:auth_provider:login_options"),
        format="json",
    )
    assert response.status_code == HTTP_200_OK
    response_json = response.json()
    assert "saml" in response_json
    assert response_json["saml"]["domain_required"] is False

    # with multiple SAML domain the domain is required to understand
    # to which IdP the user wants to login
    enterprise_data_fixture.create_saml_auth_provider()
    assert SamlAuthProviderModel.objects.count() == 2

    response = api_client.get(
        reverse("api:auth_provider:login_options"),
        format="json",
    )
    assert response.status_code == HTTP_200_OK
    response_json = response.json()
    assert "saml" in response_json
    assert response_json["saml"]["domain_required"] is True


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_admin_cannot_update_saml_provider_without_an_enterprise_license(
    api_client, data_fixture, enterprise_data_fixture
):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()
    _, unauthorized_token = data_fixture.create_user_and_token(is_staff=True)

    auth_provider_1_url = reverse(
        "api:enterprise:admin:auth_provider:item",
        kwargs={"auth_provider_id": saml_provider_1.id},
    )

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "domain": "test.it",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_402_PAYMENT_REQUIRED


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_update_saml_provider(api_client, data_fixture, enterprise_data_fixture):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()
    saml_provider_2 = enterprise_data_fixture.create_saml_auth_provider()

    _, token = enterprise_data_fixture.create_enterprise_admin_user_and_token()
    _, unauthorized_token = data_fixture.create_user_and_token()

    auth_provider_1_url = reverse(
        "api:enterprise:admin:auth_provider:item",
        kwargs={"auth_provider_id": saml_provider_1.id},
    )

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "domain": "test.it",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_403_FORBIDDEN

    response = api_client.patch(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": 9999},
        ),
        {
            "type": SamlAuthProviderType.type,
            "enabled": True,
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_404_NOT_FOUND

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "domain": saml_provider_2.domain,
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_SAML_PROVIDER_FOR_DOMAIN_ALREADY_EXISTS"

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "domain": "invalid_domain_name",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_REQUEST_BODY_VALIDATION"
    assert json.dumps(response_json["detail"]) == json.dumps(
        {
            "domain": [
                {
                    "error": "The domain value is not a valid domain name.",
                    "code": "invalid",
                }
            ]
        }
    )

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "metadata": "invalid_metadata",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_400_BAD_REQUEST
    response_json = response.json()
    assert response_json["error"] == "ERROR_REQUEST_BODY_VALIDATION"
    assert json.dumps(response_json["detail"]) == json.dumps(
        {
            "metadata": [
                {
                    "error": "The metadata is not valid according to the XML schema.",
                    "code": "invalid",
                }
            ]
        }
    )

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "domain": "test.it",
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_200_OK
    response_json = response.json()
    assert response_json["id"] == saml_provider_1.id
    assert response_json["domain"] == "test.it"

    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "enabled": False,
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_200_OK
    response_json = response.json()
    assert response_json["id"] == saml_provider_1.id
    assert response_json["enabled"] is False

    # Test that is_verified is ignored if the user tries to set it
    # This field is updated only when a user correctly logs in
    # with the SAML provider
    response = api_client.patch(
        auth_provider_1_url,
        {
            "type": SamlAuthProviderType.type,
            "is_verified": True,
        },
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json
    assert response_json["id"] == saml_provider_1.id
    assert response_json["is_verified"] is False


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_admin_cannot_delete_saml_provider_without_an_enterprise_license(
    api_client, data_fixture, enterprise_data_fixture
):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()
    _, unauthorized_token = data_fixture.create_user_and_token(is_staff=True)

    auth_provider_1_url = reverse(
        "api:enterprise:admin:auth_provider:item",
        kwargs={"auth_provider_id": saml_provider_1.id},
    )

    response = api_client.delete(
        auth_provider_1_url,
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_402_PAYMENT_REQUIRED


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_delete_saml_provider(api_client, data_fixture, enterprise_data_fixture):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()

    _, token = enterprise_data_fixture.create_enterprise_admin_user_and_token()
    _, unauthorized_token = data_fixture.create_user_and_token()

    response = api_client.delete(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": saml_provider_1.id},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_403_FORBIDDEN

    response = api_client.delete(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": 9999},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_404_NOT_FOUND

    response = api_client.delete(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": saml_provider_1.id},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_204_NO_CONTENT
    assert SamlAuthProviderModel.objects.count() == 0


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_admin_cannot_get_saml_provider_without_an_enterprise_license(
    api_client, data_fixture, enterprise_data_fixture
):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()
    _, unauthorized_token = data_fixture.create_user_and_token(is_staff=True)

    auth_provider_1_url = reverse(
        "api:enterprise:admin:auth_provider:item",
        kwargs={"auth_provider_id": saml_provider_1.id},
    )

    response = api_client.get(
        auth_provider_1_url,
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_402_PAYMENT_REQUIRED


@pytest.mark.django_db
@override_settings(DEBUG=True)
def test_get_saml_provider(api_client, data_fixture, enterprise_data_fixture):
    saml_provider_1 = enterprise_data_fixture.create_saml_auth_provider()

    _, token = enterprise_data_fixture.create_enterprise_admin_user_and_token()
    _, unauthorized_token = data_fixture.create_user_and_token()

    response = api_client.get(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": saml_provider_1.id},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {unauthorized_token}",
    )
    assert response.status_code == HTTP_403_FORBIDDEN

    response = api_client.get(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": 9999},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_404_NOT_FOUND

    response = api_client.get(
        reverse(
            "api:enterprise:admin:auth_provider:item",
            kwargs={"auth_provider_id": saml_provider_1.id},
        ),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == HTTP_200_OK
    response_json = response.json()
    assert response_json["id"] == saml_provider_1.id
    assert response_json["type"] == SamlAuthProviderType.type
    assert response_json["enabled"] is True
    assert response_json["domain"] == saml_provider_1.domain
    assert response_json["metadata"] == saml_provider_1.metadata
    assert response_json["is_verified"] is False
