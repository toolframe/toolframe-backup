"""Public SDK runtime facade for a local recovery archive catalog."""

from __future__ import annotations

import asyncio
from typing import Any

from toolframe_sdk import Plugin, PluginError

from .archive import BackupError
from .catalog import BackupCatalog

SERVICE_NAME = "backup.catalog"
_PARAMETERS = {
    "list_backups": {"limit"},
    "verify_backup": {"backup_id"},
    "retention_preview": {"max_delete"},
    "apply_retention": {"plan_token"},
}


class BackupPlugin(Plugin):
    """Inspect archives only; application snapshots belong to the stopped CLI."""

    def __init__(self, context):
        super().__init__(context)
        self.catalog: BackupCatalog | None = None

    async def activate(self):
        try:
            self.catalog = await asyncio.to_thread(
                BackupCatalog,
                self.context.config.get("destination"),
                retention_keep=self.context.config.get("retention_keep", 10),
            )
        except BackupError as error:
            raise PluginError(error.code, error.message) from None

    def _catalog(self) -> BackupCatalog:
        if self.catalog is None:
            raise PluginError(
                "backup_not_ready", "Backup catalog has not been activated."
            )
        return self.catalog

    def _application_id(self) -> str | None:
        value = self.context.call_info.get("application_id")
        return value if isinstance(value, str) and value else None

    async def _run(self, function, *args, **kwargs):
        try:
            return await asyncio.to_thread(function, *args, **kwargs)
        except BackupError as error:
            raise PluginError(error.code, error.message) from None

    async def list_backups(self, limit: int = 50) -> dict[str, Any]:
        return await self._run(
            self._catalog().list_backups,
            limit,
            application_id=self._application_id(),
        )

    async def verify_backup(self, backup_id: str) -> dict[str, Any]:
        return await self._run(
            self._catalog().verify,
            backup_id,
            application_id=self._application_id(),
        )

    async def retention_preview(self, max_delete: int = 100) -> dict[str, Any]:
        return await self._run(
            self._catalog().retention_preview,
            max_delete,
            application_id=self._application_id(),
        )

    async def apply_retention(self, plan_token: str) -> dict[str, Any]:
        return await self._run(
            self._catalog().apply_retention,
            plan_token,
            application_id=self._application_id(),
        )

    async def health(self):
        if self.catalog is None:
            return {"runtime": "not_ready", "business": "not_ready"}
        await self._run(self.catalog._directory)
        return {"runtime": "ready", "business": "ready"}

    async def invoke(self, service: str, method: str, params: dict) -> Any:
        if service != SERVICE_NAME or method not in _PARAMETERS:
            raise PluginError("method_not_found", "Unknown Backup service method.")
        if not isinstance(params, dict) or set(params) - _PARAMETERS[method]:
            raise PluginError(
                "backup_validation", "Backup method received unsupported parameters."
            )
        required = {"verify_backup": "backup_id", "apply_retention": "plan_token"}.get(
            method
        )
        if required is not None and required not in params:
            raise PluginError("backup_validation", f"{required} is required.")
        return await getattr(self, method)(**params)


__all__ = ["SERVICE_NAME", "BackupPlugin"]
