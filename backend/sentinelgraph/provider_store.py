"""Provider configuration persistence.

Credential rules enforced here:
  * A key is encrypted with Fernet before it touches the DB.
  * If no SG_MASTER_KEY is configured, DB persistence of secrets is refused and
    the operator must supply the key via environment variable. We do not fall
    back to plaintext.
  * The plaintext key is NEVER returned by any API. Responses carry a masked
    hint only.
"""
from __future__ import annotations

import json
from typing import Any

from . import ai_providers
from .config import env_provider_keys
from .db import cursor, fetchall, fetchone, get_conn, rows_to_dicts
from .security import CredentialCipher, mask_secret, redact_secrets
from .timeutil import now_iso

_cipher = CredentialCipher()


def list_configs() -> list[dict[str, Any]]:
    rows = rows_to_dicts(fetchall(
        "SELECT * FROM provider_configs ORDER BY id"))
    return [_public(r) for r in rows]


def _public(row: dict[str, Any]) -> dict[str, Any]:
    """Strip secrets, expose only a masked hint and the credential source."""
    out = dict(row)
    out.pop("secret_enc", None)

    hint = ""
    source = row.get("secret_source") or "none"
    if source == "db":
        plain = _cipher.decrypt(row.get("secret_enc"))
        hint = mask_secret(plain) if plain else "(unreadable - master key changed?)"
    elif source == "env":
        key = ai_providers.env_key_for(row.get("provider_type", ""))
        hint = mask_secret(key) if key else ""
    out["credential_hint"] = hint
    out["credential_configured"] = bool(hint)
    out["encryption_available"] = _cipher.available
    return out


def get_config(config_id: int) -> dict[str, Any] | None:
    row = fetchone(
        "SELECT * FROM provider_configs WHERE id=?", (config_id,))
    return dict(row) if row else None


def _resolve_secret(provider_type: str, secret_enc: str | None,
                    secret_source: str) -> str | None:
    if secret_source == "db":
        return _cipher.decrypt(secret_enc)
    if secret_source == "env":
        return ai_providers.env_key_for(provider_type)
    return None


def build_spec(row: dict[str, Any]) -> ai_providers.ProviderSpec:
    secret = _resolve_secret(row["provider_type"], row.get("secret_enc"),
                             row.get("secret_source") or "none")
    return ai_providers.ProviderSpec(
        provider_type=row["provider_type"],
        model_id=row["model_id"],
        api_key=secret,
        base_url=row.get("base_url"),
        timeout_s=int(row.get("timeout_s") or 60),
        max_output_tokens=row.get("max_output_tokens"),
        fast_model_id=row.get("fast_model_id"),
        allow_private=row["provider_type"] in ("ollama",),
        name=row.get("name") or "default",
    )


def active_spec() -> tuple[ai_providers.ProviderSpec | None, dict[str, Any] | None]:
    """Return the active provider spec, or None when running in core mode."""
    row = fetchone(
        "SELECT * FROM provider_configs WHERE is_active=1 LIMIT 1")
    if not row:
        return None, None
    d = dict(row)
    return build_spec(d), d


def create_config(payload: dict[str, Any]) -> dict[str, Any]:
    provider_type = payload["provider_type"]
    if provider_type not in ai_providers.PROVIDER_TYPES:
        raise ValueError(f"Unsupported provider type: {provider_type}")

    base_url = (payload.get("base_url") or "").strip() or None
    if base_url:
        from .security import SSRFError, validate_provider_url
        try:
            validate_provider_url(base_url, provider_type,
                                  allow_private=provider_type == "ollama")
        except SSRFError as exc:
            raise ValueError(str(exc)) from exc

    raw_key = (payload.get("api_key") or "").strip()
    secret_enc = None
    secret_source = "none"

    if raw_key:
        if _cipher.available:
            secret_enc = _cipher.encrypt(raw_key)
            secret_source = "db"
        else:
            raise ValueError(
                "Secure credential storage is unavailable: the master key could not be "
                "read or created. Set SG_MASTER_KEY (generate one with "
                "`python -m sentinelgraph keys`) or make the data directory writable, "
                "then retry. Alternatively leave the key empty and set the provider's "
                "environment variable (e.g. OPENAI_API_KEY)."
            )
    else:
        if ai_providers.env_key_for(provider_type):
            secret_source = "env"

    if ai_providers.PROVIDER_TYPES[provider_type]["needs_key"] and secret_source == "none":
        raise ValueError(
            f"{provider_type} requires an API key. Provide one, or set the matching "
            "environment variable before starting the server."
        )

    now = now_iso()
    with cursor() as cur:
        cur.execute(
            """INSERT INTO provider_configs
               (name,provider_type,base_url,model_id,fast_model_id,secret_enc,secret_source,
                timeout_s,max_output_tokens,is_active,allow_fallback,last_test_status,
                created_at,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (payload["name"].strip(), provider_type, base_url, payload["model_id"].strip(),
             (payload.get("fast_model_id") or "").strip() or None, secret_enc, secret_source,
             int(payload.get("timeout_s") or 60),
             payload.get("max_output_tokens"),
             1 if payload.get("is_active") else 0,
             1 if payload.get("allow_fallback") else 0,
             "untested", now, now),
        )
        new_id = cur.lastrowid
        if payload.get("is_active"):
            cur.execute("UPDATE provider_configs SET is_active=0 WHERE id<>?", (new_id,))
    return _public(get_config(new_id) or {})


def update_config(config_id: int, payload: dict[str, Any]) -> dict[str, Any]:
    row = get_config(config_id)
    if not row:
        raise ValueError("Provider configuration not found")

    fields: dict[str, Any] = {}
    for key in ("name", "model_id", "fast_model_id", "base_url"):
        if key in payload:
            val = (payload.get(key) or "").strip() or None
            fields[key] = val
    if "timeout_s" in payload:
        fields["timeout_s"] = int(payload["timeout_s"] or 60)
    if "max_output_tokens" in payload:
        fields["max_output_tokens"] = payload["max_output_tokens"]

    if fields.get("base_url"):
        from .security import SSRFError, validate_provider_url
        try:
            validate_provider_url(fields["base_url"], row["provider_type"],
                                  allow_private=row["provider_type"] == "ollama")
        except SSRFError as exc:
            raise ValueError(str(exc)) from exc

    raw_key = (payload.get("api_key") or "").strip()
    if raw_key:
        if not _cipher.available:
            raise ValueError(
                "Cannot store a new key: the master key could not be read or created. "
                "Set SG_MASTER_KEY or make the data directory writable, then retry."
            )
        fields["secret_enc"] = _cipher.encrypt(raw_key)
        fields["secret_source"] = "db"

    if payload.get("clear_credential"):
        fields["secret_enc"] = None
        fields["secret_source"] = "env" if ai_providers.env_key_for(row["provider_type"]) else "none"

    if not fields:
        return _public(row)

    fields["updated_at"] = now_iso()
    sets = ", ".join(f"{k}=?" for k in fields)
    with cursor() as cur:
        cur.execute(f"UPDATE provider_configs SET {sets} WHERE id=?",
                    (*fields.values(), config_id))
    return _public(get_config(config_id) or {})


def set_active(config_id: int, active: bool = True) -> dict[str, Any]:
    row = get_config(config_id)
    if not row:
        raise ValueError("Provider configuration not found")
    with cursor() as cur:
        if active:
            cur.execute("UPDATE provider_configs SET is_active=0")
            cur.execute("UPDATE provider_configs SET is_active=1, updated_at=? WHERE id=?",
                        (now_iso(), config_id))
        else:
            cur.execute("UPDATE provider_configs SET is_active=0, updated_at=? WHERE id=?",
                        (now_iso(), config_id))
    return _public(get_config(config_id) or {})


def delete_config(config_id: int) -> bool:
    with cursor() as cur:
        cur.execute("DELETE FROM provider_configs WHERE id=?", (config_id,))
    return True


def record_test_result(config_id: int, result: dict[str, Any]) -> None:
    with cursor() as cur:
        cur.execute(
            """UPDATE provider_configs
               SET last_test_status=?, last_test_at=?, last_test_latency_ms=?,
                   last_test_error=?, updated_at=?
               WHERE id=?""",
            ("ok" if result.get("ok") else "fail",
             result.get("checked_at"), result.get("latency_ms"),
             None if result.get("ok") else redact_secrets(result.get("error_message"))[:300],
             now_iso(), config_id),
        )


def ai_status() -> dict[str, Any]:
    """Dashboard-facing provider state. Never includes credentials."""
    spec, row = active_spec()
    if not row:
        return {
            "mode": "core_only",
            "label": "No AI provider configured",
            "detail": "All detection, correlation, graph, timeline and reporting features "
                      "run without AI.",
            "provider": None, "model": None,
            "last_test_status": None, "last_test_at": None,
            "encryption_available": _cipher.available,
            "credential_storage": _cipher.storage_info(),
        }
    d = _public(row)
    # A provider only needs a credential if its type says so. Ollama running
    # locally has no key at all, and reporting it as "missing credential" made
    # a working configuration look broken on the dashboard.
    needs_key = ai_providers.PROVIDER_TYPES[row["provider_type"]]["needs_key"]
    configured = bool(d.get("credential_configured")) or not needs_key
    return {
        "mode": "ai_enabled" if configured else "missing_credential",
        "label": f"{ai_providers.PROVIDER_TYPES[row['provider_type']]['label']} / {row['model_id']}",
        "detail": ("Provider configured and ready." if configured
                   else "Provider selected but no usable credential was found."),
        "provider": row["provider_type"],
        "model": row["model_id"],
        "credential_hint": d.get("credential_hint"),
        "last_test_status": row.get("last_test_status"),
        "last_test_at": row.get("last_test_at"),
        "encryption_available": _cipher.available,
        "credential_storage": _cipher.storage_info(),
    }
