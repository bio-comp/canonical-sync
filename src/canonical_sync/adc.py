#!/usr/bin/env python3
"""Provision or validate least-privilege authorized-user Google Drive ADC."""

from __future__ import annotations

import argparse
import json
import ntpath
import os
import stat
import sys
import tempfile
import warnings
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast

DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
ADC_FILENAME = "application_default_credentials.json"
_AUTHORIZED_USER_TYPE = "authorized_user"
_REQUIRED_AUTHORIZED_USER_FIELDS = (
    "client_id",
    "client_secret",
    "refresh_token",
    "token_uri",
)
_REQUIRED_CLIENT_FIELDS = ("client_id", "client_secret", "auth_uri", "token_uri")
_JSON_READ_ERRORS = (OSError, UnicodeError, json.JSONDecodeError)


class AdcRefreshError(RuntimeError):
    """Sanitized operator-facing failure."""


class _RefreshRequest(Protocol):
    def __call__(
        self,
        url: Any,
        method: Any = ...,
        body: Any = ...,
        headers: Any = ...,
        timeout: Any = ...,
        **kwargs: Any,
    ) -> Any: ...


class _AuthorizedUserCredential(Protocol):
    def refresh(self, request: _RefreshRequest) -> None: ...


def _is_windows(os_name: str | None = None) -> bool:
    return (os_name if os_name is not None else os.name) == "nt"


def _append_adc_filename(base: str | os.PathLike[str], *, os_name: str | None = None) -> Path:
    if _is_windows(os_name):
        return Path(ntpath.join(os.fspath(base), ADC_FILENAME))
    return Path(base).expanduser() / ADC_FILENAME


def resolve_adc_path(
    *,
    adc_path: str | os.PathLike[str] | None = None,
    cloud_sdk_config: str | os.PathLike[str] | None = None,
    environ: Mapping[str, str] | None = None,
    os_name: str | None = None,
    home: str | os.PathLike[str] | None = None,
) -> Path:
    """Resolve the writable ADC destination using the documented precedence."""

    env = os.environ if environ is None else environ
    if adc_path is not None:
        return Path(adc_path).expanduser()
    if cloud_sdk_config is not None:
        return _append_adc_filename(cloud_sdk_config, os_name=os_name)
    env_config = env.get("CLOUDSDK_CONFIG")
    if env_config:
        return _append_adc_filename(env_config, os_name=os_name)
    if _is_windows(os_name):
        appdata = env.get("APPDATA")
        if not appdata:
            raise AdcRefreshError("APPDATA is required to resolve the standard Windows ADC path")
        return Path(ntpath.join(appdata, "gcloud", ADC_FILENAME))
    home_path = Path.home() if home is None else Path(home).expanduser()
    return home_path / ".config" / "gcloud" / ADC_FILENAME


def _ensure_parent(path: Path, *, os_name: str | None = None) -> None:
    parent = path.parent
    was_missing = not parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True)
        if was_missing and not _is_windows(os_name):
            os.chmod(parent, 0o700)
    except OSError:
        raise AdcRefreshError("Unable to prepare the ADC destination directory") from None


def _restrict_file_permissions(path: Path, *, os_name: str | None = None) -> None:
    if _is_windows(os_name):
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        raise AdcRefreshError("Unable to restrict ADC file permissions") from None


def _permission_status(path: Path, *, os_name: str | None = None) -> str:
    if _is_windows(os_name):
        return "platform-N/A"
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        raise AdcRefreshError("Unable to inspect ADC file permissions") from None
    if mode != 0o600:
        raise AdcRefreshError("ADC file permissions are not owner-only (0600)")
    return "PASS"


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except _JSON_READ_ERRORS:
        raise AdcRefreshError(f"{label} is not readable valid JSON") from None
    if not isinstance(value, dict):
        raise AdcRefreshError(f"{label} must contain a JSON object")
    return value


def _validate_oauth_client_file(path: Path) -> None:
    payload = _read_json(path, label="OAuth client file")
    installed = payload.get("installed")
    if not isinstance(installed, dict):
        raise AdcRefreshError(
            "OAuth client file must be an installed/Desktop application configuration"
        )
    for field in _REQUIRED_CLIENT_FIELDS:
        value = installed.get(field)
        if not isinstance(value, str) or not value.strip():
            raise AdcRefreshError(
                "OAuth client file is missing required installed-application fields"
            )


def _scope_set(credentials: object) -> frozenset[str]:
    granted = getattr(credentials, "granted_scopes", None)
    if granted is not None:
        return frozenset(scope for scope in granted if isinstance(scope, str))
    scopes = getattr(credentials, "scopes", None)
    if scopes is None:
        return frozenset()
    return frozenset(scope for scope in scopes if isinstance(scope, str))


def _require_exact_scope(credentials: object) -> None:
    if _scope_set(credentials) != frozenset({DRIVE_READONLY_SCOPE}):
        raise AdcRefreshError("Credential scope is not exactly Drive read-only")


def _require_nonempty_string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdcRefreshError(f"Authorized-user credential is missing required {label}")
    return value


def _build_authorized_user_payload(credentials: object) -> dict[str, object]:
    _require_exact_scope(credentials)
    return {
        "type": _AUTHORIZED_USER_TYPE,
        "client_id": _require_nonempty_string(
            getattr(credentials, "client_id", None), label="client_id"
        ),
        "client_secret": _require_nonempty_string(
            getattr(credentials, "client_secret", None), label="client_secret"
        ),
        "refresh_token": _require_nonempty_string(
            getattr(credentials, "refresh_token", None), label="refresh_token"
        ),
        "token_uri": _require_nonempty_string(
            getattr(credentials, "token_uri", None), label="token_uri"
        ),
        "scopes": [DRIVE_READONLY_SCOPE],
    }


def _validate_authorized_user_payload(payload: Mapping[str, object]) -> None:
    if payload.get("type") != _AUTHORIZED_USER_TYPE:
        raise AdcRefreshError("ADC credential type must be authorized_user")
    for field in _REQUIRED_AUTHORIZED_USER_FIELDS:
        _require_nonempty_string(payload.get(field), label=field)
    if payload.get("scopes") != [DRIVE_READONLY_SCOPE]:
        raise AdcRefreshError("ADC scope list must contain exactly Drive read-only")


def _load_authorized_user_adc(path: Path) -> _AuthorizedUserCredential:
    payload = _read_json(path, label="ADC file")
    _validate_authorized_user_payload(payload)
    try:
        import google.auth
        from google.oauth2.credentials import Credentials

        # Keep the generic ADC loader as a compatibility assertion: this is the
        # path that rejected the original missing-`type` artifact. The payload
        # has already been restricted to authorized_user + exact scope above, so
        # suppress google-auth's generic externally-sourced-credential warning
        # only around this prevalidated compatibility check.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            credentials, _ = google.auth.load_credentials_from_file(  # type: ignore[no-untyped-call]
                str(path), scopes=[DRIVE_READONLY_SCOPE]
            )
    except Exception:
        raise AdcRefreshError("ADC loader rejected the authorized-user credential") from None
    if not isinstance(credentials, Credentials):
        raise AdcRefreshError("ADC credential type must be authorized_user")
    _require_nonempty_string(credentials.client_id, label="client_id")
    _require_nonempty_string(credentials.client_secret, label="client_secret")
    _require_nonempty_string(credentials.refresh_token, label="refresh_token")
    _require_nonempty_string(credentials.token_uri, label="token_uri")
    _require_exact_scope(credentials)
    return cast(_AuthorizedUserCredential, credentials)


def _default_refresh_request() -> _RefreshRequest:
    try:
        from google.auth.transport.requests import Request
    except ImportError:
        raise AdcRefreshError("google-auth is required for ADC validation") from None
    return Request()


def _verify_adc_file(
    path: Path,
    *,
    refresh: bool,
    request: _RefreshRequest | None = None,
    os_name: str | None = None,
) -> object:
    _permission_status(path, os_name=os_name)
    credentials = _load_authorized_user_adc(path)
    if refresh:
        try:
            credentials.refresh(request if request is not None else _default_refresh_request())
        except Exception:
            raise AdcRefreshError(
                "Authorized-user credential refresh/readiness validation failed"
            ) from None
        if not bool(getattr(credentials, "valid", False)):
            raise AdcRefreshError("Authorized-user credential is not refresh-ready")
        _require_exact_scope(credentials)
    return credentials


def _create_installed_app_flow(client_secrets: Path) -> object:
    try:
        from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore[import-untyped]
    except ImportError:
        raise AdcRefreshError(
            "google-auth-oauthlib is required for interactive ADC provisioning"
        ) from None
    try:
        return InstalledAppFlow.from_client_secrets_file(
            str(client_secrets), scopes=[DRIVE_READONLY_SCOPE]
        )
    except Exception:
        raise AdcRefreshError("Unable to initialize the installed-application OAuth flow") from None


def _authorize(client_secrets: Path, *, open_browser: bool, port: int) -> object:
    _validate_oauth_client_file(client_secrets)
    flow = _create_installed_app_flow(client_secrets)
    try:
        credentials = flow.run_local_server(port=port, open_browser=open_browser)  # type: ignore[attr-defined]
    except Exception:
        raise AdcRefreshError("OAuth authorization failed") from None
    _require_exact_scope(credentials)
    return credentials


def _write_candidate(
    path: Path, payload: Mapping[str, object], *, os_name: str | None = None
) -> Path:
    _ensure_parent(path, os_name=os_name)
    try:
        descriptor, temp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent), text=True
        )
    except OSError:
        raise AdcRefreshError("Unable to create a temporary ADC candidate") from None
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(dict(payload), handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _restrict_file_permissions(temp_path, os_name=os_name)
    except Exception as exc:
        with suppress(OSError):
            temp_path.unlink(missing_ok=True)
        if isinstance(exc, AdcRefreshError):
            raise
        raise AdcRefreshError("Unable to serialize the temporary ADC candidate") from None
    return temp_path


def _replace_atomically(candidate: Path, destination: Path, *, os_name: str | None = None) -> None:
    try:
        os.replace(candidate, destination)
    except OSError:
        raise AdcRefreshError("Unable to atomically replace the ADC destination") from None
    _restrict_file_permissions(destination, os_name=os_name)


def check_adc(
    destination: Path,
    *,
    request: _RefreshRequest | None = None,
    os_name: str | None = None,
) -> None:
    if not destination.is_file():
        raise AdcRefreshError("ADC file does not exist")
    _verify_adc_file(destination, refresh=True, request=request, os_name=os_name)


def refresh_adc(
    *,
    client_secrets: Path,
    destination: Path,
    open_browser: bool = True,
    port: int = 0,
    force: bool = False,
    request: _RefreshRequest | None = None,
    os_name: str | None = None,
) -> None:
    if destination.exists() and not force:
        try:
            check_adc(destination, request=request, os_name=os_name)
        except AdcRefreshError:
            raise AdcRefreshError(
                "Refusing to replace an existing ADC without --force; inspect it with --check first"
            ) from None
        raise AdcRefreshError("Existing ADC is already valid; use --force to reauthorize it")

    credentials = _authorize(client_secrets, open_browser=open_browser, port=port)
    payload = _build_authorized_user_payload(credentials)
    candidate: Path | None = None
    try:
        candidate = _write_candidate(destination, payload, os_name=os_name)
        _verify_adc_file(candidate, refresh=True, request=request, os_name=os_name)
        _replace_atomically(candidate, destination, os_name=os_name)
        candidate = None
        _verify_adc_file(destination, refresh=False, os_name=os_name)
    finally:
        if candidate is not None:
            with suppress(OSError):
                candidate.unlink(missing_ok=True)


def _status_lines(destination: Path, *, os_name: str | None = None) -> tuple[str, ...]:
    return (
        f"ADC path: {destination}",
        "credential type: authorized_user",
        "scope: drive.readonly",
        f"permissions: {_permission_status(destination, os_name=os_name)}",
        "load: PASS",
        "refresh/readiness: PASS",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Provision or validate an exact-scope Google Drive read-only authorized-user ADC."
        )
    )
    parser.add_argument("--client-secrets", type=Path, help="Installed/Desktop OAuth client JSON")
    parser.add_argument("--adc-path", type=Path, help="Explicit ADC destination path")
    parser.add_argument(
        "--cloud-sdk-config",
        type=Path,
        help="Cloud SDK configuration directory containing application_default_credentials.json",
    )
    parser.add_argument(
        "--no-open-browser",
        action="store_true",
        help="Do not automatically launch a browser; localhost callback is still required",
    )
    parser.add_argument(
        "--port", type=int, default=0, help="Local OAuth callback port (default: 0)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Authorize replacement of an existing ADC; validation is never bypassed",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Validate the existing ADC noninteractively",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.port < 0 or args.port > 65535:
        parser.error("--port must be between 0 and 65535")
    if args.check and args.force:
        parser.error("--force cannot be combined with --check")
    if not args.check and args.client_secrets is None:
        parser.error("--client-secrets is required unless --check is used")

    try:
        destination = resolve_adc_path(
            adc_path=args.adc_path,
            cloud_sdk_config=args.cloud_sdk_config,
        )
        if args.check:
            check_adc(destination)
        else:
            assert args.client_secrets is not None
            refresh_adc(
                client_secrets=args.client_secrets.expanduser(),
                destination=destination,
                open_browser=not args.no_open_browser,
                port=args.port,
                force=args.force,
            )
        for line in _status_lines(destination):
            print(line)
        return 0
    except AdcRefreshError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("ERROR: ADC refresh failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
