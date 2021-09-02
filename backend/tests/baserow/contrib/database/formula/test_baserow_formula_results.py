import sys

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework.status import HTTP_200_OK

from baserow.contrib.database.fields.models import FormulaField

VALID_FORMULA_TESTS = [
    ("'test'", "test"),
    ("UPPER('test')", "TEST"),
    ("LOWER('TEST')", "test"),
    ("LOWER(UPPER('test'))", "test"),
    ("LOWER(UPPER('test'))", "test"),
    ("CONCAT('test', ' ', 'works')", "test works"),
    ("CONCAT('test', ' ', UPPER('works'))", "test WORKS"),
    (
        "UPPER(" * 100 + "'test'" + ")" * 100,
        "TEST",
    ),
    (
        "UPPER('" + "t" * settings.MAX_FORMULA_STRING_LENGTH + "')",
        "T" * settings.MAX_FORMULA_STRING_LENGTH,
    ),
    ("'https://उदाहरण.परीक्षा'", "https://उदाहरण.परीक्षा"),
    ("UPPER('https://उदाहरण.परीक्षा')", "HTTPS://उदाहरण.परीक्षा"),
    ("CONCAT('https://उदाहरण.परीक्षा', '/api')", "https://उदाहरण.परीक्षा/api"),
    ("LOWER('HTTPS://उदाहरण.परीक्षा')", "https://उदाहरण.परीक्षा"),
    ("CONCAT('\ntest', '\n')", "\ntest\n"),
    ("1+1", "2"),
]


def a_test_case(name, starting_table_setup, formula_info, expectation):
    return name, starting_table_setup, formula_info, expectation


def given_a_table(columns, rows):
    return columns, rows


def when_a_formula_field_is_added(formula):
    return formula


def when_multiple_formula_fields_are_added(formulas):
    return formulas


def then_expect_the_rows_to_be(rows):
    return rows


COMPLEX_VALID_TESTS = [
    a_test_case(
        "Can reference and add to a integer column",
        given_a_table(columns=[("number", "number")], rows=[[1], [2], [None]]),
        when_a_formula_field_is_added("field('number')+1"),
        then_expect_the_rows_to_be([["1", "2"], ["2", "3"], [None, None]]),
    ),
    a_test_case(
        "Can reference and add to a integer column",
        given_a_table(columns=[("number", "number")], rows=[[1], [2], [None]]),
        when_multiple_formula_fields_are_added(
            [("formula_1", "field('number')+1"), "field('formula_1')+1"]
        ),
        then_expect_the_rows_to_be(
            [["1", "2", "3"], ["2", "3", "4"], [None, None, None]]
        ),
    ),
]
INVALID_FORMULA_TESTS = [
    (
        "test",
        "ERROR_PARSING_FORMULA",
        (
            "The formula failed to parse due to: Invalid syntax at line 1, col 4: "
            "mismatched input 'the end of the formula' expecting '('."
        ),
    ),
    (
        "UPPER(" * (sys.getrecursionlimit())
        + "'test'"
        + ")" * (sys.getrecursionlimit()),
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: it exceeded the maximum formula size.",
    ),
    (
        "CONCAT(" + ",".join(["'test'"] * 5000) + ")",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: it exceeded the maximum formula size.",
    ),
    (
        "UPPER('" + "t" * (settings.MAX_FORMULA_STRING_LENGTH + 1) + "')",
        "ERROR_MAPPING_FORMULA",
        "The formula failed to map to a valid formula due to: an embedded "
        f"string in the formula over the maximum length of "
        f"{settings.MAX_FORMULA_STRING_LENGTH} .",
    ),
    (
        "CONCAT()",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function concat. It excepts more than 1 arguments but "
        "instead 0 were given.",
    ),
    (
        "CONCAT('a')",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function concat. It excepts more than 1 arguments but "
        "instead 1 were given.",
    ),
    (
        "UPPER()",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function upper. It excepts exactly 1 arguments but "
        "instead 0 were given.",
    ),
    (
        "LOWER()",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function lower. It excepts exactly 1 arguments but "
        "instead 0 were given.",
    ),
    (
        "UPPER('a','a')",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function upper. It excepts exactly 1 arguments but "
        "instead 2 were given.",
    ),
    (
        "LOWER('a','a')",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function lower. It excepts exactly 1 arguments but "
        "instead 2 were given.",
    ),
    (
        "LOWER('a', CONCAT())",
        "ERROR_PARSING_FORMULA",
        "The formula failed to parse due to: An invalid number of arguments were "
        "provided to the function lower. It excepts exactly 1 arguments but "
        "instead 2 were given.",
    ),
    ("'a' + 2", "ERROR_COMPILING_FORMULA", None),
    ("CONCAT('a',2)", "ERROR_COMPILING_FORMULA", None),
    ("CONCAT(1,2)", "ERROR_COMPILING_FORMULA", None),
    ("UPPER(1,2)", "ERROR_PARSING_FORMULA", None),
    ("UPPER(1)", "ERROR_COMPILING_FORMULA", None),
    ("LOWER(1,2)", "ERROR_PARSING_FORMULA", None),
    ("LOWER(1)", "ERROR_COMPILING_FORMULA", None),
]


@pytest.mark.parametrize("test_input,expected", VALID_FORMULA_TESTS)
@pytest.mark.django_db
def test_valid_formulas(test_input, expected, data_fixture, api_client):
    user, token = data_fixture.create_user_and_token()
    table = data_fixture.create_database_table(user=user)
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "Formula2", "type": "formula", "formula": test_input},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200, response.json()
    field_id = response.json()["id"]
    response = api_client.post(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200
    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{field_id}"] == expected


@pytest.mark.parametrize("name,table_setup,formula,expected", COMPLEX_VALID_TESTS)
@pytest.mark.django_db
def test_valid_complex_formulas(
    name,
    table_setup,
    formula,
    expected,
    data_fixture,
    api_client,
    django_assert_num_queries,
):
    user, token = data_fixture.create_user_and_token()
    table, fields, rows = data_fixture.build_table(
        columns=table_setup[0], rows=table_setup[1], user=user
    )
    if not isinstance(formula, list):
        formula = [formula]
    formula_field_ids = []
    j = 0
    for f in formula:
        if not isinstance(f, tuple):
            f = f"baserow_formula_{j}", f
            j += 1
        response = api_client.post(
            reverse("api:database:fields:list", kwargs={"table_id": table.id}),
            {"name": f[0], "type": "formula", "formula": f[1]},
            format="json",
            HTTP_AUTHORIZATION=f"JWT {token}",
        )
        assert response.status_code == 200, response.json()
        formula_field_ids.append(response.json()["id"])
    response = api_client.post(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200
    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == len(table_setup[1]) + 1
    i = 0
    for row in expected:
        k = 0
        for field in fields:
            assert response_json["results"][i][f"field_{field.id}"] == row[k]
            k += 1
        for f_id in formula_field_ids:
            assert response_json["results"][i][f"field_{f_id}"] == row[k]
            k += 1
        i += 1


@pytest.mark.parametrize("test_input,error,detail", INVALID_FORMULA_TESTS)
@pytest.mark.django_db
def test_invalid_formulas(test_input, error, detail, data_fixture, api_client):
    user, token = data_fixture.create_user_and_token()
    table = data_fixture.create_database_table(user=user)
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "Formula2", "type": "formula", "formula": test_input},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 400
    response_json = response.json()
    assert response_json["error"] == error
    if detail:
        assert response_json["detail"] == detail

    response = api_client.get(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200
    assert response.json() == []
    assert FormulaField.objects.count() == 0


@pytest.mark.django_db
def test_valid_formulas2(data_fixture, api_client, django_assert_num_queries):
    test_input = "field('number')+1"
    expected = "2"
    user, token = data_fixture.create_user_and_token()
    table = data_fixture.create_database_table(user=user)
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "number", "type": "number", "number_type": "INTEGER"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200, response.json()
    number_field_id = response.json()["id"]
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "Formula2", "type": "formula", "formula": test_input},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200, response.json()
    formula_field_id = response.json()["id"]
    response = api_client.post(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {f"field_{number_field_id}": 1},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    row_id = response.json()["id"]
    assert response.status_code == 200, response.json()
    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == expected

    response = api_client.patch(
        reverse(
            "api:database:rows:item", kwargs={"table_id": table.id, "row_id": row_id}
        ),
        {f"field_{number_field_id}": 2},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    assert response.status_code == 200, response.json()

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "3"


@pytest.mark.django_db
def test_changing_type_of_reference_field_to_invalid_one_for_formula(
    api_client, data_fixture
):
    user, token = data_fixture.create_user_and_token(
        email="test@test.nl", password="password", first_name="Test1"
    )
    table, fields, rows = data_fixture.build_table(
        columns=[("number", "number")], rows=[[1]], user=user
    )
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "Formula", "type": "formula", "formula": "field('number')+1"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json
    formula_field_id = response_json["id"]

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "2"

    response = api_client.patch(
        reverse("api:database:fields:item", kwargs={"field_id": fields[0].id}),
        {"type": "boolean"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "2"

    response = api_client.get(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json
    assert "argument 0 invalid" in response_json[1]["error"]


@pytest.mark.django_db
def test_changing_type_of_reference_field_to_invalid_one_for_formula(
    api_client, data_fixture
):
    user, token = data_fixture.create_user_and_token(
        email="test@test.nl", password="password", first_name="Test1"
    )
    table, fields, rows = data_fixture.build_table(
        columns=[("number", "number")], rows=[[1]], user=user
    )
    response = api_client.post(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        {"name": "Formula", "type": "formula", "formula": "field('number')+1"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json
    formula_field_id = response_json["id"]

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "2"

    response = api_client.patch(
        reverse("api:database:fields:item", kwargs={"field_id": fields[0].id}),
        {"type": "boolean"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "2"

    response = api_client.get(
        reverse("api:database:fields:list", kwargs={"table_id": table.id}),
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json
    assert "argument 0 invalid" in response_json[1]["error"]

    response = api_client.patch(
        reverse("api:database:fields:item", kwargs={"field_id": formula_field_id}),
        {"name": "Formula", "type": "formula", "formula": "1"},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response.status_code == HTTP_200_OK, response_json

    response = api_client.get(
        reverse("api:database:rows:list", kwargs={"table_id": table.id}),
        {},
        format="json",
        HTTP_AUTHORIZATION=f"JWT {token}",
    )
    response_json = response.json()
    assert response_json["count"] == 1
    assert response_json["results"][0][f"field_{formula_field_id}"] == "1"