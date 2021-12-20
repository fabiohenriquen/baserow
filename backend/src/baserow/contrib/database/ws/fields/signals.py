from django.dispatch import receiver
from django.db import transaction

from baserow.contrib.database.ws.public import broadcast_event_to_a_tables_public_views
from baserow.ws.registries import page_registry

from baserow.contrib.database.fields import signals as field_signals
from baserow.contrib.database.fields.registries import field_type_registry
from baserow.contrib.database.api.fields.serializers import FieldSerializer


def _broadcast_to_table_and_public_views(data, field, user):
    table_page_type = page_registry.get("table")
    table_page_type.broadcast(
        data,
        getattr(user, "web_socket_id", None),
        table_id=field.table_id,
    )
    broadcast_event_to_a_tables_public_views(field.table, data, field=field)


@receiver(field_signals.field_created)
def field_created(sender, field, related_fields, user, **kwargs):
    transaction.on_commit(
        lambda: _broadcast_to_table_and_public_views(
            {
                "type": "field_created",
                "field": field_type_registry.get_serializer(
                    field, FieldSerializer
                ).data,
                "related_fields": [
                    field_type_registry.get_serializer(f, FieldSerializer).data
                    for f in related_fields
                ],
            },
            field,
            user,
        )
    )


@receiver(field_signals.field_restored)
def field_restored(sender, field, related_fields, user, **kwargs):
    transaction.on_commit(
        lambda: _broadcast_to_table_and_public_views(
            {
                "type": "field_restored",
                "field": field_type_registry.get_serializer(
                    field, FieldSerializer
                ).data,
                "related_fields": [
                    field_type_registry.get_serializer(f, FieldSerializer).data
                    for f in related_fields
                ],
            },
            field,
            user,
        )
    )


@receiver(field_signals.field_updated)
def field_updated(sender, field, related_fields, user, **kwargs):
    transaction.on_commit(
        lambda: _broadcast_to_table_and_public_views(
            {
                "type": "field_updated",
                "field_id": field.id,
                "field": field_type_registry.get_serializer(
                    field, FieldSerializer
                ).data,
                "related_fields": [
                    field_type_registry.get_serializer(f, FieldSerializer).data
                    for f in related_fields
                ],
            },
            field,
            user,
        )
    )


@receiver(field_signals.field_deleted)
def field_deleted(sender, field_id, field, related_fields, user, **kwargs):
    # TODO need to precalculate field deleted
    transaction.on_commit(
        lambda: _broadcast_to_table_and_public_views(
            {
                "type": "field_deleted",
                "table_id": field.table_id,
                "field_id": field_id,
                "related_fields": [
                    field_type_registry.get_serializer(f, FieldSerializer).data
                    for f in related_fields
                ],
            },
            field,
            user,
        )
    )
