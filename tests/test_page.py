"""Native Dashboard checks using fake public service responses."""

from __future__ import annotations


def app():
    import streamlit as st
    from toolframe_sdk import PluginError

    from toolframe_backup.page import render

    def summary(number):
        return {
            "id": f"{number:032x}",
            "created_at": f"2026-01-{number:02d}T00:00:00Z",
            "application_id": "app-1",
            "application_name": "Recovery app",
            "composition_revision": "revision-1",
            "file_count": 2,
            "total_bytes": 512,
            "archive_sha256": "a" * 64,
            "verified": True,
            "last_verified_at": "2026-01-04T00:00:00Z",
        }

    class FakeService:
        def call(self, method, params=None, *, timeout=30):
            assert timeout == 120
            st.session_state.setdefault("calls", []).append((method, params))
            if method == "list_backups":
                if st.session_state.get("catalog_error"):
                    raise PluginError(
                        "backup_permissions",
                        "Backup destination must have permissions 0700.",
                    )
                backups = (
                    [summary(2)]
                    if st.session_state.get("deleted")
                    else [summary(2), summary(1)]
                )
                if st.session_state.get("empty"):
                    backups = []
                return {
                    "backups": backups,
                    "count": len(backups),
                    "verified_count": len(backups),
                    "rejected_count": 1,
                    "rejected": [{"id": "f" * 32, "error_code": "checksum_mismatch"}],
                    "limit": 100,
                    "destination": "/srv/backup-test",
                    "destination_kind": "local",
                    "retention_keep": 1,
                    "status": "destination_missing"
                    if st.session_state.get("missing")
                    else "ready",
                    "guidance": "Stop the application, then use toolframe-backup create with the configured destination.",
                }
            if method == "verify_backup":
                if st.session_state.get("verify_error"):
                    raise PluginError(
                        "checksum_mismatch", "Archive checksum does not match."
                    )
                return summary(2)
            if method == "retention_preview":
                return {
                    "plan_token": "b" * 64,
                    "expires_at": "2026-01-04T00:10:00Z",
                    "retention_keep": 1,
                    "eligible_count": 2,
                    "delete_count": 1,
                    "delete": [summary(1)],
                    "remaining_count": 1,
                    "max_delete": params["max_delete"],
                    "preserved_rejected_count": 1,
                }
            if method == "apply_retention":
                if st.session_state.get("retention_stale"):
                    raise PluginError(
                        "backup_retention_stale",
                        "Backup catalog changed. Preview retention again.",
                    )
                st.session_state["deleted"] = True
                return {"deleted_ids": [f"{1:032x}"], "deleted_count": 1}
            raise AssertionError(method)

    class FakeServices:
        def require(self, name, *, version=1):
            assert name == "backup.catalog"
            assert version == 1
            return FakeService()

    class FakeContext:
        services = FakeServices()

        def can(self, scope):
            assert scope == "system.plugins.manage"
            return st.session_state.get("manage", True)

    render(FakeContext())


def _test_app(**state):
    from streamlit.testing.v1 import AppTest

    result = AppTest.from_function(app, default_timeout=60)
    for key, value in state.items():
        result.session_state[key] = value
    result.run()
    assert not result.exception
    return result


def _button(result, label):
    return next(button for button in result.button if button.label == label)


def test_catalog_page_shows_status_and_stopped_workflow():
    result = _test_app()
    assert result.title[0].value == "Backups"
    assert [(metric.label, metric.value) for metric in result.metric] == [
        ("Verified backups", "2"),
        ("Rejected candidates", "1"),
    ]
    assert (
        "--home APPLICATION_HOME --directory BACKUP_DIRECTORY" in result.code[0].value
    )
    assert any("Stop the application" in info.value for info in result.info)
    assert any("unencrypted" in caption.value for caption in result.caption)
    assert any("Manage plugins" in caption.value for caption in result.caption)
    assert not any(
        "Create" in button.label or "Restore" in button.label
        for button in result.button
    )


def test_read_only_dashboard_has_catalog_without_management_controls():
    result = _test_app(manage=False)
    assert len(result.metric) == 2
    assert {button.label for button in result.button} == {"Refresh catalog"}
    assert any(caption.value == "Read-only access" for caption in result.caption)
    assert all(method == "list_backups" for method, _ in result.session_state["calls"])


def test_verification_only_sends_validated_catalog_id():
    result = _test_app()
    _button(result, "Verify selected backup").click().run()
    assert not result.exception
    assert ("verify_backup", {"backup_id": f"{2:032x}"}) in result.session_state[
        "calls"
    ]
    assert any(
        "passed structure and checksum verification" in success.value
        for success in result.success
    )


def test_retention_requires_preview_and_confirmation():
    result = _test_app()
    assert not any(
        button.label == "Delete previewed backups" for button in result.button
    )
    _button(result, "Preview retention").click().run()
    assert _button(result, "Delete previewed backups").disabled
    assert not any(
        method == "apply_retention" for method, _ in result.session_state["calls"]
    )
    result.checkbox[0].check().run()
    assert not _button(result, "Delete previewed backups").disabled
    _button(result, "Delete previewed backups").click().run()
    assert not result.exception
    assert ("apply_retention", {"plan_token": "b" * 64}) in result.session_state[
        "calls"
    ]
    assert any(
        success.value == "Deleted 1 verified backups." for success in result.success
    )
    assert "backup-retention-preview" not in result.session_state


def test_stale_retention_shows_error_and_requires_new_preview():
    result = _test_app()
    _button(result, "Preview retention").click().run()
    result.session_state["retention_stale"] = True
    result.checkbox[0].check().run()
    _button(result, "Delete previewed backups").click().run()
    assert not result.exception
    assert any("Preview retention again" in error.value for error in result.error)
    assert "backup-retention-preview" not in result.session_state
    assert "deleted" not in result.session_state


def test_refresh_invalidates_displayed_preview():
    result = _test_app()
    _button(result, "Preview retention").click().run()
    _button(result, "Refresh catalog").click().run()
    assert not any(
        button.label == "Delete previewed backups" for button in result.button
    )
    assert "backup-retention-preview" not in result.session_state


def test_errors_missing_directory_and_empty_catalog_are_actionable():
    result = _test_app(catalog_error=True)
    assert result.error[0].value == "Backup destination must have permissions 0700."
    assert not result.button
    result = _test_app(missing=True, empty=True)
    assert any("does not exist yet" in warning.value for warning in result.warning)
    assert any(
        info.value == "No verified backups for this application."
        for info in result.info
    )
    assert not any(button.label == "Verify selected backup" for button in result.button)
    result = _test_app(verify_error=True)
    _button(result, "Verify selected backup").click().run()
    assert result.error[0].value == "Archive checksum does not match."
