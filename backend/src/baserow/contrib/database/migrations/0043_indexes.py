# Generated by Django 2.2.11 on 2021-06-14 09:08
from django.db import migrations, models, connection


def forward(apps, schema_editor):
    # noinspection PyPep8Naming
    Table = apps.get_model("database", "Table")

    with connection.schema_editor() as tables_schema_editor:
        # We need to stop the transaction because we might need to lock a lot of tables
        # which could result in an out of memory exception.
        tables_schema_editor.atomic.__exit__(None, None, None)

        for table in Table.objects.all().order_by("id"):
            table_name = f"database_table_{table.id}"
            # Make the forward migration more idempotent / resilient to partially
            # applied migrations due to the lack of a transaction by using IF NOT
            # EXISTS.
            query = (
                f"CREATE INDEX IF NOT EXISTS idx_table_{table.id}_trashed ON"
                f" public.{table_name}(trashed);"
            )
            try:
                tables_schema_editor.execute(query)
                print(f"worked for {table_name}")
            except:
                print(query)


def reverse(apps, schema_editor):
    # noinspection PyPep8Naming
    Table = apps.get_model("database", "Table")

    with connection.schema_editor() as tables_schema_editor:
        # We need to stop the transaction because we might need to lock a lot of tables
        # which could result in an out of memory exception.
        tables_schema_editor.atomic.__exit__(None, None, None)

        # apps.get_model doesn't return a model using our custom overridden managers
        # so we can safely use .objects which will return all trashed tables also
        for table in Table.objects.all():
            table_name = f"database_table_{table.id}"
            # Make the reverse migration more idempotent / resilient to partially
            # applied migrations due to the lack of a transaction by using IF EXISTS.
            tables_schema_editor.execute(
                f"DROP INDEX IF EXISTS idx_table_{table.id}_trashed"
            )


class Migration(migrations.Migration):

    dependencies = [
        ("database", "0042_auto_20211104_1144"),
    ]

    operations = [
        migrations.RunPython(forward, reverse),
    ]