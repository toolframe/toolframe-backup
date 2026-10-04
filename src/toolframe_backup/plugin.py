"""Scoped Backup catalog, Dashboard and read-only MCP declarations."""

from __future__ import annotations

from toolframe_sdk import (
    AuthorizationSpec,
    MethodSpec,
    PluginDefinition,
    Resource,
    ScopeSpec,
    ServiceSpec,
)

SERVICE_NAME = "backup.catalog"
_ID = {"type": "string", "pattern": "^[0-9a-f]{32}$"}
_HASH = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_SUMMARY_PROPERTIES = {
    "id": _ID,
    "created_at": {"type": "string"},
    "application_id": {"type": "string"},
    "application_name": {"type": "string"},
    "composition_revision": {"type": ["string", "null"]},
    "file_count": {"type": "integer", "minimum": 0},
    "total_bytes": {"type": "integer", "minimum": 0},
    "archive_sha256": _HASH,
    "verified": {"const": True},
    "last_verified_at": {"type": "string"},
}
SUMMARY_SCHEMA = {
    "type": "object",
    "properties": _SUMMARY_PROPERTIES,
    "required": list(_SUMMARY_PROPERTIES),
    "additionalProperties": False,
}


def _input(properties: dict, required: tuple[str, ...] = ()) -> dict:
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


LIST_INPUT = _input(
    {"limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 50}}
)
_LIST_PROPERTIES = {
    "backups": {"type": "array", "items": SUMMARY_SCHEMA, "maxItems": 100},
    "count": {"type": "integer", "minimum": 0, "maximum": 100},
    "verified_count": {"type": "integer", "minimum": 0, "maximum": 1000},
    "rejected_count": {"type": "integer", "minimum": 0, "maximum": 1000},
    "rejected": {
        "type": "array",
        "maxItems": 100,
        "items": {
            "type": "object",
            "properties": {"id": _ID, "error_code": {"type": "string"}},
            "required": ["id", "error_code"],
            "additionalProperties": False,
        },
    },
    "limit": {"type": "integer", "minimum": 1, "maximum": 100},
    "destination": {"type": "string"},
    "destination_kind": {"const": "local"},
    "retention_keep": {"type": "integer", "minimum": 1, "maximum": 1000},
    "status": {"enum": ["ready", "destination_missing"]},
    "guidance": {"type": "string"},
}
LIST_OUTPUT = {
    "type": "object",
    "properties": _LIST_PROPERTIES,
    "required": list(_LIST_PROPERTIES),
    "additionalProperties": False,
}
_PREVIEW_PROPERTIES = {
    "plan_token": _HASH,
    "expires_at": {"type": "string"},
    "retention_keep": {"type": "integer", "minimum": 1, "maximum": 1000},
    "eligible_count": {"type": "integer", "minimum": 0, "maximum": 1000},
    "delete_count": {"type": "integer", "minimum": 0, "maximum": 100},
    "delete": {"type": "array", "items": SUMMARY_SCHEMA, "maxItems": 100},
    "remaining_count": {"type": "integer", "minimum": 0, "maximum": 1000},
    "max_delete": {"type": "integer", "minimum": 1, "maximum": 100},
    "preserved_rejected_count": {"type": "integer", "minimum": 0, "maximum": 1000},
}
PREVIEW_OUTPUT = {
    "type": "object",
    "properties": _PREVIEW_PROPERTIES,
    "required": list(_PREVIEW_PROPERTIES),
    "additionalProperties": False,
}

plugin = PluginDefinition(
    id="backup",
    factory="toolframe_backup.service:BackupPlugin",
    authorization=AuthorizationSpec(
        scopes={
            "backup.read": ScopeSpec(title="Read the local Backup catalog"),
        }
    ),
    config_schema={
        "type": "object",
        "properties": {
            "destination": {
                "type": "string",
                "minLength": 1,
                "description": "Operator-configured absolute local directory with mode 0700.",
            },
            "retention_keep": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000,
                "default": 10,
            },
        },
        "required": ["destination"],
        "additionalProperties": False,
    },
    services={
        SERVICE_NAME: ServiceSpec(
            methods={
                "list_backups": MethodSpec(
                    audience="business",
                    required_scopes=("backup.read",),
                    description="List verified local recovery archives for this application. This does not snapshot a running application.",
                    input_schema=LIST_INPUT,
                    output_schema=LIST_OUTPUT,
                    read_only=True,
                ),
                "verify_backup": MethodSpec(
                    audience="system",
                    required_scopes=("system.plugins.manage",),
                    description="Recheck one configured archive's structure and checksums; hashes are not authentication signatures.",
                    input_schema=_input({"backup_id": _ID}, ("backup_id",)),
                    output_schema=SUMMARY_SCHEMA,
                    read_only=True,
                ),
                "retention_preview": MethodSpec(
                    audience="system",
                    required_scopes=("system.plugins.manage",),
                    description="Preview bounded deletion of this application's oldest verified archives without removing them.",
                    input_schema=_input(
                        {
                            "max_delete": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100,
                                "default": 100,
                            }
                        }
                    ),
                    output_schema=PREVIEW_OUTPUT,
                    read_only=True,
                ),
                "apply_retention": MethodSpec(
                    audience="system",
                    required_scopes=("system.plugins.manage",),
                    description="Apply an unexpired unchanged retention preview after re-verification; unknown files are preserved.",
                    input_schema=_input({"plan_token": _HASH}, ("plan_token",)),
                    output_schema={
                        "type": "object",
                        "properties": {
                            "deleted_ids": {
                                "type": "array",
                                "items": _ID,
                                "maxItems": 100,
                            },
                            "deleted_count": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100,
                            },
                        },
                        "required": ["deleted_ids", "deleted_count"],
                        "additionalProperties": False,
                    },
                ),
            }
        )
    },
    resources=(
        Resource(
            id="main",
            kind="dashboard.page",
            title="Backups",
            required_scopes=("backup.read",),
            data={"entrypoint": "toolframe_backup.page:render", "order": 40},
        ),
        Resource(
            id="list_backups",
            kind="mcp.tool",
            title="List backups",
            required_scopes=("backup.read",),
            data={
                "service": SERVICE_NAME,
                "method": "list_backups",
                "description": "Read the verified recovery archive catalog. Creating or restoring backups requires the stopped-application operator CLI.",
                "input_schema": LIST_INPUT,
                "output_schema": LIST_OUTPUT,
            },
        ),
        Resource(
            id="usage",
            kind="llms.document",
            title="Backup catalog and recovery workflow",
            data={"package": "toolframe_backup", "path": "docs/usage.md"},
        ),
    ),
)

__all__ = [
    "LIST_INPUT",
    "LIST_OUTPUT",
    "PREVIEW_OUTPUT",
    "SERVICE_NAME",
    "SUMMARY_SCHEMA",
    "plugin",
]
