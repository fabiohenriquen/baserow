# Generated by Django 3.2.6 on 2021-11-01 09:38
import django.db.models.deletion
from django.core.exceptions import ObjectDoesNotExist
from django.db import migrations, models

from baserow.contrib.database.formula import FormulaHandler


# noinspection PyPep8Naming


def reverse(apps, schema_editor):
    pass


def get_or_create_node(field, FieldDependencyNode):
    if hasattr(field, "fieldnode"):
        return field.fieldnode
    else:
        field, _ = FieldDependencyNode.objects.get_or_create(
            field=field, table=field.table
        )
        field.fieldnode = field
        return field


def _get_or_create_node_from_name(referenced_field_name, table, FieldDependencyNode):
    try:
        referenced_field = table.field_set.get(name=referenced_field_name)
    except ObjectDoesNotExist:
        referenced_field = None
    if referenced_field is not None:
        referenced_field_dependency_node = get_or_create_node(
            referenced_field, FieldDependencyNode
        )
        return referenced_field_dependency_node
    else:
        return _construct_broken_reference_node(
            referenced_field_name, table, FieldDependencyNode
        )


def _construct_broken_reference_node(referenced_field_name, table, FieldDependencyNode):
    node, _ = FieldDependencyNode.objects.get_or_create(
        table=table,
        broken_reference_field_name=referenced_field_name,
    )
    return node


# noinspection PyPep8Naming
def forward(apps, schema_editor):
    FormulaField = apps.get_model("database", "FormulaField")
    FieldDependencyEdge = apps.get_model("database", "FieldDependencyEdge")
    FieldDependencyNode = apps.get_model("database", "FieldDependencyNode")
    LinkRowField = apps.get_model("database", "LinkRowField")

    _build_graph_from_scratch(
        FieldDependencyEdge, FieldDependencyNode, FormulaField, LinkRowField
    )
    _calculate_all_formula_internal_fields_in_order(FormulaField, FieldDependencyNode)


# noinspection PyPep8Naming
def _build_graph_from_scratch(
    FieldDependencyEdge, FieldDependencyNode, FormulaField, LinkRowField
):
    for link_row in LinkRowField.objects.all():
        link_row_node = get_or_create_node(link_row, FieldDependencyNode)
        related_primary_field = next(
            f for f in link_row.link_row_table.field_set.all() if f.primary
        )
        primary_node = get_or_create_node(related_primary_field, FieldDependencyNode)
        FieldDependencyEdge.objects.create(
            parent=primary_node, via=link_row, child=link_row_node
        )

    for formula in FormulaField.objects.all():
        expr = FormulaHandler.raw_formula_to_untyped_expression(formula.formula)
        dependency_field_names = (
            FormulaHandler.get_direct_field_name_dependencies_from_expression(
                formula.table, expr
            )
        )

        for new_dependency_field_name in dependency_field_names:
            table = formula.table
            field_node = get_or_create_node(formula, FieldDependencyNode)
            referenced_field_dependency_node = _get_or_create_node_from_name(
                new_dependency_field_name,
                table,
                FieldDependencyNode,
            )
            FieldDependencyEdge.objects.create(
                parent=referenced_field_dependency_node, child=field_node
            )


# noinspection PyPep8Naming
def _calculate_all_formula_internal_fields_in_order(FormulaField, FieldDependencyNode):
    already_fixed_fields = set()
    for formula in FormulaField.objects.all():
        if formula not in already_fixed_fields:
            field_node = get_or_create_node(formula, FieldDependencyNode)
            _recursively_setup_parents(FormulaField, already_fixed_fields, field_node)
            _setup_field(already_fixed_fields, formula)


# noinspection PyPep8Naming
def _recursively_setup_parents(FormulaField, already_fixed_fields, field_node):
    for parent_node in field_node.parents.all():
        if hasattr(parent_node, "field"):
            try:
                formula_field = FormulaField.objects.get(id=parent_node.field_id)
                _recursively_setup_parents(
                    FormulaField, already_fixed_fields, formula_field
                )
                _setup_field(already_fixed_fields, formula_field)
            except FormulaField.DoesNotExist:
                pass


def _setup_field(already_fixed_fields, formula_field):
    expression = FormulaHandler.calculate_typed_expression(formula_field, None)
    expression_type = expression.expression_type

    formula_field.internal_formula = str(expression)
    expression_type.persist_onto_formula_field(formula_field)
    formula_field.requires_refresh_after_insert = (
        FormulaHandler.formula_requires_refresh_on_insert(expression)
    )
    formula_field.save()
    already_fixed_fields.add(formula_field)


class Migration(migrations.Migration):

    dependencies = [
        ("database", "0040_formulafield_remove_field_by_id"),
    ]

    operations = [
        migrations.CreateModel(
            name="FieldDependencyEdge",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="formulafield",
            name="internal_formula",
            field=models.TextField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="formulafield",
            name="requires_refresh_after_insert",
            field=models.BooleanField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="FieldDependencyNode",
            fields=[
                (
                    "id",
                    models.AutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "broken_reference_field_name",
                    models.TextField(blank=True, null=True),
                ),
                (
                    "children",
                    models.ManyToManyField(
                        blank=True,
                        related_name="parents",
                        through="database.FieldDependencyEdge",
                        to="database.FieldDependencyNode",
                    ),
                ),
                (
                    "field",
                    models.OneToOneField(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="nodes",
                        to="database.field",
                    ),
                ),
                (
                    "table",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="nodes",
                        to="database.table",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="fielddependencyedge",
            name="child",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="parent_edges",
                to="database.fielddependencynode",
            ),
        ),
        migrations.AddField(
            model_name="fielddependencyedge",
            name="parent",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="children_edges",
                to="database.fielddependencynode",
            ),
        ),
        migrations.AddField(
            model_name="fielddependencyedge",
            name="via",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="vias",
                to="database.field",
            ),
        ),
        migrations.RunPython(forward, reverse),
        migrations.AlterField(
            model_name="formulafield",
            name="internal_formula",
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name="formulafield",
            name="requires_refresh_after_insert",
            field=models.BooleanField(),
        ),
    ]