"""Typed errors (spec section 4.4).

Each typed code maps to one exit code. Exit 2 is a usage or configuration error. Exit 1 is a failure,
or a judging result such as `drift`. The two tables below copy section 4.4. A test checks them against the spec.
"""

from __future__ import annotations

# Codes that exit 2: usage or configuration (spec section 4.4, exit 2 row).
_USAGE_CODES = (
    "usage", "flag_not_valid", "config_missing", "config_invalid", "unknown_field", "duplicate_key",
    "schema_unsupported", "realm_required", "realm_mismatch", "owner_required", "admin_realm_refused",
    "builtin_client", "credential_missing", "insecure_url", "image_invalid", "volume_invalid",
    "audit_required", "unsafe_path", "unsafe_file_mode", "secrets_server_mismatch",
    "secret_managed_public", "id_invalid",
)

# Codes that exit 1: a failed command or a judging result (spec section 4.4, exit 1 table).
_FAILURE_CODES = (
    "drift", "confirm_required", "plan_changed", "needs_adopt", "owner_conflict",
    "allow_delete_required", "allow_remote_required", "reenable_refused", "secrets_mismatch",
    "secrets_missing", "generation_pending", "generation_unknown", "generation_pruned",
    "temporary_password_missing", "runtime_missing", "runtime_failed", "runtime_timeout",
    "runtime_ambiguous", "container_state", "container_exited", "port_in_use", "keycloak_unreachable",
    "keycloak_timeout", "auth_failed", "keycloak_rejected", "id_conflict", "email_duplicate",
    "not_found", "realm_absent", "secrets_unreadable", "audit_failed", "audit_incomplete", "locked",
    "file_failed", "secret_in_export", "apply_partial",
)

# Typed code -> exit code.
EXIT_CODES: dict[str, int] = {code: 2 for code in _USAGE_CODES} | {code: 1 for code in _FAILURE_CODES}


class KcAxiError(Exception):
    """A failure with a typed code. The secret reader of section 5.8 raises the same type."""

    def __init__(self, code: str, message: str, help: tuple[str, ...] | list[str] = (), **fields):
        if code not in EXIT_CODES:
            raise KeyError(f"unregistered error code: {code}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.help = tuple(help)
        self.fields = fields

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.code]
