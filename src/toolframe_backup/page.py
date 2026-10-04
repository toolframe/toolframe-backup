"""Native Dashboard catalog and explicit retention through public SDK services."""

from __future__ import annotations

from toolframe_sdk import PageContext, PluginError

from .service import SERVICE_NAME

_PLAN_KEY = "backup-retention-preview"
_NOTICE_KEY = "backup-notice"


def _rows(backups: list[dict]) -> list[dict]:
    return [
        {
            "Backup ID": item["id"],
            "Created": item["created_at"],
            "Files": item["file_count"],
            "Payload bytes": item["total_bytes"],
            "Last verified": item["last_verified_at"],
        }
        for item in backups
    ]


def render(context: PageContext) -> None:
    """The page never reads an application home or creates a live snapshot."""
    import streamlit as st

    st.title("Backups")
    service = context.services.require(SERVICE_NAME, version=1)
    try:
        result = service.call("list_backups", {"limit": 100}, timeout=120)
    except PluginError as error:
        st.error(error.message)
        return

    st.caption(f"Local destination: {result['destination']}")
    st.caption(
        f"Retention policy: keep the newest {result['retention_keep']} verified backups for this application. Deletion requires a preview and confirmation."
    )
    st.info(result["guidance"])
    st.code(
        "toolframe-backup create --home APPLICATION_HOME --directory BACKUP_DIRECTORY",
        language="bash",
    )
    st.caption(
        "Replace the placeholders with the stopped application's home and the configured local destination. Archives are unencrypted and contain protected application files. Checksums detect corruption; they are not authentication signatures."
    )
    if result["status"] == "destination_missing":
        st.warning(
            "The configured backup directory does not exist yet. The stopped CLI can create it with protected permissions."
        )

    st.button("Refresh catalog", on_click=lambda: st.session_state.pop(_PLAN_KEY, None))
    verified_column, rejected_column = st.columns(2)
    verified_column.metric("Verified backups", result["verified_count"])
    rejected_column.metric("Rejected candidates", result["rejected_count"])
    notice = st.session_state.pop(_NOTICE_KEY, None)
    if notice:
        st.success(notice)
    if result["backups"]:
        st.dataframe(_rows(result["backups"]), hide_index=True, width="stretch")
        if result["verified_count"] > len(result["backups"]):
            st.caption(
                "Showing the newest 100 verified backups. Retention considers the complete bounded catalog."
            )
    else:
        st.info("No verified backups for this application.")
    if result["rejected"]:
        st.warning(
            "Rejected candidates are preserved. Inspect them with the operator CLI before taking any action."
        )
        st.dataframe(result["rejected"], hide_index=True, width="stretch")
    if not context.can("system.plugins.manage"):
        st.caption("Read-only access")
        return

    st.subheader("Verify an archive")
    st.caption(
        "Archive verification and retention require the Manage plugins operator permission."
    )
    if result["backups"]:
        selected = st.selectbox("Backup ID", [item["id"] for item in result["backups"]])
        if st.button("Verify selected backup"):
            try:
                verified = service.call(
                    "verify_backup", {"backup_id": selected}, timeout=120
                )
            except PluginError as error:
                st.error(error.message)
            else:
                st.success(
                    f"Backup {verified['id']} passed structure and checksum verification."
                )
                st.caption(f"Archive SHA-256: {verified['archive_sha256']}")
    else:
        st.caption("Create a stopped-application archive before verifying it here.")

    st.subheader("Explicit retention")
    with st.form("backup-retention-preview-form"):
        max_delete = st.number_input(
            "Maximum backups to delete in this action",
            min_value=1,
            max_value=100,
            value=100,
            step=1,
        )
        if st.form_submit_button("Preview retention"):
            try:
                st.session_state[_PLAN_KEY] = service.call(
                    "retention_preview", {"max_delete": max_delete}, timeout=120
                )
            except PluginError as error:
                st.session_state.pop(_PLAN_KEY, None)
                st.error(error.message)
    plan = st.session_state.get(_PLAN_KEY)
    if plan is None:
        return
    st.caption(
        f"Preview expires at {plan['expires_at']}. Catalog changes require a new preview."
    )
    if not plan["delete_count"]:
        st.success("No verified backups exceed the retention policy.")
        return
    st.warning(
        f"This action will permanently delete {plan['delete_count']} verified backups and leave {plan['remaining_count']} verified backups. Unknown files and rejected archives are preserved."
    )
    st.dataframe(_rows(plan["delete"]), hide_index=True, width="stretch")
    confirmed = st.checkbox(
        "I confirm deletion of the previewed backups.",
        key=f"backup-confirm-{plan['plan_token']}",
    )
    if st.button("Delete previewed backups", disabled=not confirmed):
        try:
            result = service.call(
                "apply_retention", {"plan_token": plan["plan_token"]}, timeout=120
            )
        except PluginError as error:
            st.session_state.pop(_PLAN_KEY, None)
            st.error(error.message)
        else:
            st.session_state.pop(_PLAN_KEY, None)
            st.session_state[_NOTICE_KEY] = (
                f"Deleted {result['deleted_count']} verified backups."
            )
            st.rerun()


__all__ = ["render"]
