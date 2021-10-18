import pytest
from django.core.management import call_command
from django.db import DEFAULT_DB_ALIAS

# noinspection PyPep8Naming
from django.db import connection
from django.db.migrations.executor import MigrationExecutor

migrate_from = [("database", "0039_formulafield")]
migrate_to = [("database", "0040_formulafield_remove_field_by_id")]


# noinspection PyPep8Naming
@pytest.mark.django_db
def test_migration_fixes_duplicate_field_names(data_fixture, transactional_db):
    old_state = migrate(migrate_from)

    # The models used by the data_fixture below are not touched by this migration so
    # it is safe to use the latest version in the test.
    user = data_fixture.create_user()
    table = data_fixture.create_database_table(user=user)
    text_field = data_fixture.create_text_field(user=user, table=table, name="text")
    FormulaField = old_state.apps.get_model("database", "FormulaField")
    ContentType = old_state.apps.get_model("contenttypes", "ContentType")
    content_type_id = ContentType.objects.get_for_model(FormulaField).id
    formula_field = FormulaField.objects.create(
        table_id=table.id,
        formula_type="text",
        formula=f"field_by_id({text_field.id})",
        content_type_id=content_type_id,
        order=0,
    )
    unknown_field_by_id = FormulaField.objects.create(
        table_id=table.id,
        formula_type="text",
        formula=f"field_by_id(9999)",
        content_type_id=content_type_id,
        order=0,
    )

    new_state = migrate(migrate_to)
    NewFormulaField = new_state.apps.get_model("database", "FormulaField")

    new_formula_field = NewFormulaField.objects.get(id=formula_field.id)
    assert new_formula_field.formula == "field('text')"
    assert (
        new_formula_field.old_formula_with_field_by_id
        == f"field_by_id({text_field.id})"
    )
    new_unknown_field_by_id = NewFormulaField.objects.get(id=unknown_field_by_id.id)
    assert new_unknown_field_by_id.formula == "field('unknown field 9999')"
    assert new_unknown_field_by_id.old_formula_with_field_by_id == f"field_by_id(9999)"

    # We need to apply the latest migration otherwise other tests might fail.
    call_command("migrate", verbosity=0, database=DEFAULT_DB_ALIAS)


def migrate(target):
    executor = MigrationExecutor(connection)
    executor.loader.build_graph()  # reload.
    executor.migrate(target)
    new_state = executor.loader.project_state(target)
    return new_state
