# Generated by Django 3.2.6 on 2021-12-01 16:32

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("database", "0049_urlfield_2_textfield"),
    ]

    operations = [
        migrations.CreateModel(
            name="GalleryView",
            fields=[
                (
                    "view_ptr",
                    models.OneToOneField(
                        auto_created=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        parent_link=True,
                        primary_key=True,
                        serialize=False,
                        to="database.view",
                    ),
                ),
            ],
            options={
                "abstract": False,
            },
            bases=("database.view",),
        ),
        migrations.CreateModel(
            name="GalleryViewFieldOptions",
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
                    "hidden",
                    models.BooleanField(
                        default=True,
                        help_text="Whether or not the field should be hidden in the "
                                  "card.",
                    ),
                ),
                (
                    "order",
                    models.SmallIntegerField(
                        default=32767,
                        help_text="The order that the field has in the form. Lower "
                                  "value is first.",
                    ),
                ),
                (
                    "field",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="database.field"
                    ),
                ),
                (
                    "gallery_view",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="database.galleryview",
                    ),
                ),
            ],
            options={
                "ordering": ("order", "field_id"),
            },
        ),
        migrations.AddField(
            model_name="galleryview",
            name="field_options",
            field=models.ManyToManyField(
                through="database.GalleryViewFieldOptions", to="database.Field"
            ),
        ),
    ]