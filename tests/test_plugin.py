"""SDK declarations and runtime catalog behavior; hosted authorization is separate."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from importlib.resources import files

import pytest
from test_catalog import fake_verify, write_candidate
from toolframe_sdk import (
    SYSTEM_SCOPES,
    PluginError,
    Principal,
    RuntimeContext,
    call_context,
    validate,
)

from toolframe_backup import catalog
from toolframe_backup.plugin import plugin
from toolframe_backup.service import SERVICE_NAME, BackupPlugin


@contextmanager
def caller(application_id="app-1"):
    token = call_context.set({"application_id": application_id})
    try:
        yield
    finally:
        call_context.reset(token)


@pytest.fixture
async def runtime(tmp_path, monkeypatch):
    destination = tmp_path.resolve() / "archives"
    destination.mkdir(mode=0o700)
    monkeypatch.setattr(catalog, "verify_backup", fake_verify)
    context = RuntimeContext(
        None,
        plugin_id="backup",
        generation="generation-1",
        config={"destination": str(destination), "retention_keep": 1},
    )
    service = BackupPlugin(context)
    await service.activate()
    return destination, service


def test_definition_has_ordinary_plugin_scoped_methods_and_read_only_mcp():
    assert plugin.id == "backup"
    assert plugin.kind == "business"
    assert plugin.provider_kind is None
    assert plugin.requires == {}
    assert plugin.store is None
    assert plugin.authorization.scopes.keys() == {"backup.read"}
    assert plugin.services[SERVICE_NAME].version == 1
    methods = plugin.services[SERVICE_NAME].methods
    assert methods["list_backups"].audience == "business"
    assert methods["list_backups"].required_scopes == ("backup.read",)
    for name in ("verify_backup", "retention_preview", "apply_retention"):
        assert methods[name].audience == "system"
        assert methods[name].required_scopes == ("system.plugins.manage",)
    assert all(not method.public_api for method in methods.values())
    assert methods["list_backups"].read_only
    assert not methods["apply_retention"].read_only
    resources = {(item.kind, item.id): item for item in plugin.resources}
    tool = resources[("mcp.tool", "list_backups")]
    assert tool.required_scopes == ("backup.read",)
    assert tool.data["method"] == "list_backups"
    assert tool.data["input_schema"]["properties"]["limit"]["maximum"] == 100
    assert resources[("dashboard.page", "main")].required_scopes == ("backup.read",)
    usage = resources[("llms.document", "usage")]
    assert (
        "stopped"
        in files(usage.data["package"]).joinpath(usage.data["path"]).read_text()
    )


def test_sdk_principal_contract_denies_read_only_and_all_business_management():
    scope_catalog = {
        name: spec.model_dump() for name, spec in plugin.authorization.scopes.items()
    }
    scope_catalog.update({name: {"category": "system"} for name in SYSTEM_SCOPES})
    readers = [
        Principal(kind="mcp_key", scopes=("backup.read",)),
        Principal(kind="public", all_business=True),
    ]
    methods = plugin.services[SERVICE_NAME].methods
    for principal in readers:
        assert principal.allows(methods["list_backups"].required_scopes, scope_catalog)
        for name in ("verify_backup", "retention_preview", "apply_retention"):
            assert not principal.allows(methods[name].required_scopes, scope_catalog)
    manager = Principal(
        kind="password", scopes=("backup.read", "system.plugins.manage")
    )
    assert all(
        manager.allows(method.required_scopes, scope_catalog)
        for method in methods.values()
    )


async def test_runtime_filters_application_and_only_retains_matching_archives(runtime):
    destination, service = runtime
    first = write_candidate(destination, 1)
    second = write_candidate(destination, 2)
    other = write_candidate(destination, 3, application_id="other-app")
    with caller():
        result = await service.invoke(SERVICE_NAME, "list_backups", {})
        assert [item["id"] for item in result["backups"]] == [f"{2:032x}", f"{1:032x}"]
        validate(
            plugin.services[SERVICE_NAME].methods["list_backups"].output_schema, result
        )
        verified = await service.invoke(
            SERVICE_NAME, "verify_backup", {"backup_id": f"{1:032x}"}
        )
        validate(
            plugin.services[SERVICE_NAME].methods["verify_backup"].output_schema,
            verified,
        )
        with pytest.raises(PluginError) as error:
            await service.verify_backup(f"{3:032x}")
        assert error.value.code == "backup_identity"
        plan = await service.retention_preview(max_delete=1)
        validate(
            plugin.services[SERVICE_NAME].methods["retention_preview"].output_schema,
            plan,
        )
        applied = await service.apply_retention(plan["plan_token"])
        validate(
            plugin.services[SERVICE_NAME].methods["apply_retention"].output_schema,
            applied,
        )
    assert not first.exists()
    assert second.exists() and other.exists()


@pytest.mark.parametrize(
    "method,params",
    [
        ("list_backups", {"limit": True}),
        ("list_backups", {"limit": 101}),
        ("list_backups", {"path": "/somewhere"}),
        ("verify_backup", {}),
        ("verify_backup", {"backup_id": "../outside"}),
        ("retention_preview", {"max_delete": 0}),
        ("apply_retention", {}),
        ("apply_retention", {"plan_token": "wrong"}),
    ],
)
async def test_runtime_rejects_unsafe_or_unbounded_parameters(runtime, method, params):
    _, service = runtime
    with caller(), pytest.raises(PluginError) as error:
        await service.invoke(SERVICE_NAME, method, params)
    assert error.value.code == "backup_validation"


async def test_unknown_service_method_and_missing_host_identity(runtime):
    _, service = runtime
    for name, method in (
        ("other", "list_backups"),
        (SERVICE_NAME, "create_live_backup"),
    ):
        with pytest.raises(PluginError) as error:
            await service.invoke(name, method, {})
        assert error.value.code == "method_not_found"
    with pytest.raises(PluginError) as error:
        await service.retention_preview()
    assert error.value.code == "backup_identity_missing"


async def test_io_runs_outside_event_loop_thread(runtime, monkeypatch):
    _, service = runtime
    event_loop_thread = threading.get_ident()
    observed = []
    original = service.catalog.list_backups

    def track(*args, **kwargs):
        observed.append(threading.get_ident())
        return original(*args, **kwargs)

    monkeypatch.setattr(service.catalog, "list_backups", track)
    with caller():
        await service.list_backups()
    assert observed and observed[0] != event_loop_thread


async def test_activation_needs_configuration_and_never_changes_permissions(tmp_path):
    context = RuntimeContext(None, plugin_id="backup", generation="generation-1")
    with pytest.raises(PluginError) as error:
        await BackupPlugin(context).activate()
    assert error.value.code == "backup_configuration"
    destination = tmp_path.resolve() / "public-directory"
    destination.mkdir(mode=0o755)
    destination.chmod(0o755)
    context.config = {"destination": str(destination)}
    with pytest.raises(PluginError) as error:
        await BackupPlugin(context).activate()
    assert error.value.code == "backup_permissions"
    assert destination.stat().st_mode & 0o777 == 0o755
