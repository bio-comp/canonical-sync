from __future__ import annotations

import json
import os
import stat
import warnings
from collections.abc import Mapping
from importlib.metadata import version
from pathlib import Path
from typing import Any

import pytest
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow  # type: ignore[import-untyped]

import canonical_sync.adc as adc


class _Response:
    def __init__(self, status: int, payload: Mapping[str, object]) -> None:
        self.status = status
        self.data = json.dumps(dict(payload)).encode("utf-8")
        self.headers: dict[str, str] = {}


class _SuccessRequest:
    def __call__(self, *args: object, **kwargs: object) -> _Response:
        del args, kwargs
        return _Response(
            200,
            {
                "access_token": "synthetic-access-token",
                "expires_in": 3600,
                "scope": adc.DRIVE_READONLY_SCOPE,
                "token_type": "Bearer",
            },
        )


class _FailureRequest:
    def __call__(self, *args: object, **kwargs: object) -> _Response:
        del args, kwargs
        return _Response(400, {"error": "invalid_grant"})


class _FakeFlow:
    def __init__(
        self, *, credentials: object | None = None, failure: Exception | None = None
    ) -> None:
        self.credentials = credentials
        self.failure = failure
        self.calls: list[dict[str, object]] = []

    def run_local_server(self, **kwargs: object) -> object:
        self.calls.append(dict(kwargs))
        if self.failure is not None:
            raise self.failure
        assert self.credentials is not None
        return self.credentials


def _credentials(*, scopes: list[str] | None = None) -> Credentials:
    return Credentials(  # type: ignore[no-untyped-call]
        token="synthetic-access-token",
        refresh_token="synthetic-refresh-token",
        token_uri="https://oauth2.googleapis.com/token",
        client_id="synthetic-client-id",
        client_secret="synthetic-client-secret",
        scopes=scopes or [adc.DRIVE_READONLY_SCOPE],
    )


def _client_file(tmp_path: Path) -> Path:
    path = tmp_path / "oauth client.json"
    path.write_text(
        json.dumps(
            {
                "installed": {
                    "client_id": "synthetic-client-id",
                    "client_secret": "synthetic-client-secret",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def _valid_payload() -> dict[str, object]:
    return {
        "type": "authorized_user",
        "client_id": "synthetic-client-id",
        "client_secret": "synthetic-client-secret",
        "refresh_token": "synthetic-refresh-token",
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": [adc.DRIVE_READONLY_SCOPE],
    }


def _write_adc(path: Path, payload: Mapping[str, object] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(dict(payload or _valid_payload())), encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o600)


def _install_flow(monkeypatch: pytest.MonkeyPatch, flow: _FakeFlow) -> None:
    monkeypatch.setattr(adc, "_create_installed_app_flow", lambda _path: flow)


def test_exact_versions_and_no_legacy_console_flow() -> None:
    assert version("google-auth") == "2.62.0"
    assert version("google-auth-oauthlib") == "1.5.0"
    assert not hasattr(InstalledAppFlow, "run_console")


def test_explicit_adc_path_has_highest_precedence(tmp_path: Path) -> None:
    explicit = tmp_path / "explicit path" / "adc.json"
    resolved = adc.resolve_adc_path(
        adc_path=explicit,
        cloud_sdk_config=tmp_path / "other",
        environ={"CLOUDSDK_CONFIG": str(tmp_path / "env")},
        home=tmp_path / "home",
    )
    assert resolved == explicit


def test_explicit_cloud_sdk_config_resolution(tmp_path: Path) -> None:
    base = tmp_path / "cloud config with spaces"
    assert adc.resolve_adc_path(cloud_sdk_config=base, environ={}) == base / adc.ADC_FILENAME


def test_environment_cloud_sdk_config_resolution(tmp_path: Path) -> None:
    base = tmp_path / "env cloud config"
    assert adc.resolve_adc_path(environ={"CLOUDSDK_CONFIG": str(base)}) == base / adc.ADC_FILENAME


def test_posix_standard_default_resolution(tmp_path: Path) -> None:
    assert adc.resolve_adc_path(environ={}, os_name="posix", home=tmp_path) == (
        tmp_path / ".config" / "gcloud" / adc.ADC_FILENAME
    )


def test_windows_standard_default_resolution() -> None:
    appdata = r"C:\Users\Example User\AppData\Roaming"
    resolved = adc.resolve_adc_path(environ={"APPDATA": appdata}, os_name="nt")
    assert str(resolved) == nt_expected(appdata)


def nt_expected(appdata: str) -> str:
    return appdata + r"\gcloud\application_default_credentials.json"


def test_google_application_credentials_is_not_a_writable_default(
    tmp_path: Path,
) -> None:
    resolved = adc.resolve_adc_path(
        environ={"GOOGLE_APPLICATION_CREDENTIALS": str(tmp_path / "do-not-touch.json")},
        os_name="posix",
        home=tmp_path / "home",
    )
    assert resolved == tmp_path / "home" / ".config" / "gcloud" / adc.ADC_FILENAME


def test_installed_desktop_client_validation_rejects_web_config(tmp_path: Path) -> None:
    path = tmp_path / "web.json"
    path.write_text(
        json.dumps(
            {
                "web": {
                    "client_id": "synthetic-client-id",
                    "client_secret": "synthetic-client-secret",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(adc.AdcRefreshError, match="installed/Desktop"):
        adc._validate_oauth_client_file(path)


def test_valid_output_has_authorized_user_type_and_exact_scope(tmp_path: Path) -> None:
    path = tmp_path / "adc.json"
    candidate = adc._write_candidate(path, adc._build_authorized_user_payload(_credentials()))
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        assert payload["type"] == "authorized_user"
        assert payload["scopes"] == [adc.DRIVE_READONLY_SCOPE]
        adc._verify_adc_file(candidate, refresh=True, request=_SuccessRequest())
    finally:
        candidate.unlink(missing_ok=True)


def test_adc_loader_compatibility_check_is_warning_quiet(tmp_path: Path) -> None:
    path = tmp_path / "adc.json"
    _write_adc(path)
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        adc._load_authorized_user_adc(path)
    assert not [warning for warning in captured if issubclass(warning.category, DeprecationWarning)]


def test_unexpected_broader_oauth_scope_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flow = _FakeFlow(
        credentials=_credentials(
            scopes=[
                adc.DRIVE_READONLY_SCOPE,
                "https://www.googleapis.com/auth/cloud-platform",
            ]
        )
    )
    _install_flow(monkeypatch, flow)
    with pytest.raises(adc.AdcRefreshError, match="exactly Drive read-only"):
        adc.refresh_adc(
            client_secrets=_client_file(tmp_path),
            destination=tmp_path / "adc.json",
            request=_SuccessRequest(),
        )
    assert not (tmp_path / "adc.json").exists()


def test_plain_credentials_to_json_is_not_a_completed_adc_artifact(
    tmp_path: Path,
) -> None:
    path = tmp_path / "adc.json"
    path.write_text(_credentials().to_json(), encoding="utf-8")  # type: ignore[no-untyped-call]
    if os.name != "nt":
        path.chmod(0o600)
    assert "type" not in json.loads(path.read_text(encoding="utf-8"))
    with pytest.raises(adc.AdcRefreshError, match="credential type"):
        adc._load_authorized_user_adc(path)


@pytest.mark.parametrize("missing", ["refresh_token", "client_id", "client_secret"])
def test_missing_required_authorized_user_fields_are_rejected(tmp_path: Path, missing: str) -> None:
    payload = _valid_payload()
    del payload[missing]
    path = tmp_path / f"missing-{missing}.json"
    _write_adc(path, payload)
    with pytest.raises(adc.AdcRefreshError, match=missing):
        adc._load_authorized_user_adc(path)


def test_existing_adc_is_byte_identical_when_oauth_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "adc.json"
    original = b"existing-credential-bytes\n"
    destination.write_bytes(original)
    if os.name != "nt":
        destination.chmod(0o600)
    flow = _FakeFlow(failure=RuntimeError("SENSITIVE_OAUTH_FAILURE_SENTINEL"))
    _install_flow(monkeypatch, flow)
    with pytest.raises(adc.AdcRefreshError, match="OAuth authorization failed"):
        adc.refresh_adc(
            client_secrets=_client_file(tmp_path),
            destination=destination,
            force=True,
            request=_SuccessRequest(),
        )
    assert destination.read_bytes() == original


def test_existing_adc_is_byte_identical_when_candidate_refresh_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "adc.json"
    original = b"existing-credential-bytes\n"
    destination.write_bytes(original)
    if os.name != "nt":
        destination.chmod(0o600)
    _install_flow(monkeypatch, _FakeFlow(credentials=_credentials()))
    with pytest.raises(adc.AdcRefreshError, match="refresh/readiness"):
        adc.refresh_adc(
            client_secrets=_client_file(tmp_path),
            destination=destination,
            force=True,
            request=_FailureRequest(),
        )
    assert destination.read_bytes() == original


def test_atomic_replace_occurs_only_after_candidate_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "adc.json"
    _install_flow(monkeypatch, _FakeFlow(credentials=_credentials()))
    validated = False
    original_verify = adc._verify_adc_file
    original_replace = adc.os.replace

    def verify_wrapper(
        path: Path,
        *,
        refresh: bool,
        request: adc._RefreshRequest | None = None,
        os_name: str | None = None,
    ) -> object:
        nonlocal validated
        result = original_verify(path, refresh=refresh, request=request, os_name=os_name)
        if path != destination and refresh:
            validated = True
        return result

    def replace_wrapper(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes], dest: Any
    ) -> None:
        assert validated
        original_replace(source, dest)

    monkeypatch.setattr(adc, "_verify_adc_file", verify_wrapper)
    monkeypatch.setattr(adc.os, "replace", replace_wrapper)
    adc.refresh_adc(
        client_secrets=_client_file(tmp_path),
        destination=destination,
        request=_SuccessRequest(),
    )
    assert validated
    assert destination.exists()


def test_parent_directory_creation_and_paths_with_spaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    destination = tmp_path / "parent with spaces" / "nested" / adc.ADC_FILENAME
    _install_flow(monkeypatch, _FakeFlow(credentials=_credentials()))
    adc.refresh_adc(
        client_secrets=_client_file(tmp_path),
        destination=destination,
        request=_SuccessRequest(),
    )
    assert destination.is_file()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission assertion")
def test_posix_final_mode_is_0600(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    destination = tmp_path / "adc.json"
    _install_flow(monkeypatch, _FakeFlow(credentials=_credentials()))
    adc.refresh_adc(
        client_secrets=_client_file(tmp_path),
        destination=destination,
        request=_SuccessRequest(),
    )
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def test_windows_permission_path_does_not_call_posix_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "adc.json"
    path.write_text("{}", encoding="utf-8")

    def forbidden_chmod(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("chmod must not be used for the Windows branch")

    monkeypatch.setattr(adc.os, "chmod", forbidden_chmod)
    adc._restrict_file_permissions(path, os_name="nt")
    assert adc._permission_status(path, os_name="nt") == "platform-N/A"


def test_cli_does_not_expose_scope_override() -> None:
    option_strings = {
        option for action in adc._build_parser()._actions for option in action.option_strings
    }
    assert "--scope" not in option_strings
    assert "--scopes" not in option_strings


def test_no_open_browser_is_forwarded_to_local_server(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flow = _FakeFlow(credentials=_credentials())
    _install_flow(monkeypatch, flow)
    adc.refresh_adc(
        client_secrets=_client_file(tmp_path),
        destination=tmp_path / "adc.json",
        open_browser=False,
        port=0,
        request=_SuccessRequest(),
    )
    assert flow.calls == [{"port": 0, "open_browser": False}]


def test_existing_valid_adc_requires_force_for_reauthorization(tmp_path: Path) -> None:
    destination = tmp_path / "adc.json"
    _write_adc(destination)
    with pytest.raises(adc.AdcRefreshError, match="use --force"):
        adc.refresh_adc(
            client_secrets=_client_file(tmp_path),
            destination=destination,
            request=_SuccessRequest(),
        )


def test_check_mode_does_not_start_oauth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    destination = tmp_path / "adc.json"
    _write_adc(destination)
    monkeypatch.setattr(adc, "_default_refresh_request", lambda: _SuccessRequest())

    def forbidden_flow(_path: Path) -> object:
        raise AssertionError("OAuth flow must not start in --check mode")

    monkeypatch.setattr(adc, "_create_installed_app_flow", forbidden_flow)
    assert adc.main(["--check", "--adc-path", str(destination)]) == 0
    captured = capsys.readouterr()
    assert "credential type: authorized_user" in captured.out
    assert "refresh/readiness: PASS" in captured.out
    assert captured.err == ""


def test_success_output_contains_no_token_or_client_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    destination = tmp_path / "adc.json"
    _write_adc(destination)
    monkeypatch.setattr(adc, "_default_refresh_request", lambda: _SuccessRequest())
    assert adc.main(["--check", "--adc-path", str(destination)]) == 0
    output = capsys.readouterr().out
    assert "synthetic-refresh-token" not in output
    assert "synthetic-access-token" not in output
    assert "synthetic-client-secret" not in output
    assert "client_secret" not in output
    assert "refresh_token" not in output


def test_failure_output_sanitizes_oauth_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = "SENSITIVE_OAUTH_FAILURE_SENTINEL"
    _install_flow(monkeypatch, _FakeFlow(failure=RuntimeError(sentinel)))
    result = adc.main(
        [
            "--client-secrets",
            str(_client_file(tmp_path)),
            "--adc-path",
            str(tmp_path / "adc.json"),
        ]
    )
    captured = capsys.readouterr()
    assert result == 1
    assert sentinel not in captured.out
    assert sentinel not in captured.err
    assert "OAuth authorization failed" in captured.err


def test_helper_contains_no_consumer_authority_semantics() -> None:
    source = Path(adc.__file__).read_text(encoding="utf-8").lower()
    forbidden = (
        "consumer-specific authority",
        "project reconciliation status",
        "canonical object id",
        "publication authorization",
        "scientific policy",
    )
    assert all(term not in source for term in forbidden)
