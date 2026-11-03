from __future__ import annotations

import hashlib
import json
import random
import re
import time
from collections.abc import Callable
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .domain import AuthorityObjectSpec, SourceContent, SourceObservation, TransportProvenance
from .errors import (
    TransportAuthError,
    TransportNotFoundError,
    TransportPermissionError,
    TransportPermanentError,
    TransportTransientError,
    UnsupportedRepresentationError,
)

DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
DRIVE_METADATA_FIELDS = (
    "id,name,mimeType,version,modifiedTime,parents,trashed,capabilities(canDownload)"
)
GOOGLE_DOC_MARKDOWN_REPRESENTATION = "google-drive-export-markdown-v1"
GOOGLE_DRIVE_FILE_DOWNLOAD_REPRESENTATION = "google-drive-file-download-v1"
_GOOGLE_DOC_MIME = "application/vnd.google-apps.document"
_MARKDOWN_MIME = "text/markdown"
_GOOGLE_NATIVE_MIME_PREFIX = "application/vnd.google-apps."
_RAW_DOWNLOAD_FIELDS = "id,mimeType,size,sha256Checksum,capabilities(canDownload)"
_TRANSIENT_STATUSES = frozenset({429, 500, 502, 503, 504})
_GOOGLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class _Request(Protocol):
    def execute(self) -> object: ...


class _FilesResource(Protocol):
    def get(self, **kwargs: object) -> _Request: ...
    def export(self, **kwargs: object) -> _Request: ...
    def get_media(self, **kwargs: object) -> _Request: ...
    def list(self, **kwargs: object) -> _Request: ...


class _DriveService(Protocol):
    def files(self) -> _FilesResource: ...


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _CapabilitiesWire(_WireModel):
    canDownload: bool


class _DriveMetadataWire(_WireModel):
    id: str
    name: str
    mimeType: str
    version: str
    modifiedTime: str
    parents: list[str] = Field(default_factory=list)
    trashed: bool
    capabilities: _CapabilitiesWire


class _DriveListWire(_WireModel):
    files: list[_DriveMetadataWire]
    nextPageToken: str | None = None


class _RawDownloadMetadataWire(_WireModel):
    id: str
    mimeType: str
    size: str | None = None
    sha256Checksum: str | None = None
    capabilities: _CapabilitiesWire


def _raw_download_contract(
    raw: object, spec: AuthorityObjectSpec
) -> tuple[int | None, str | None]:
    try:
        wire = _RawDownloadMetadataWire.model_validate(raw, strict=True)
    except ValidationError as exc:
        raise TransportPermanentError("Drive stored-file metadata failed strict validation") from exc
    if wire.id != spec.object_id or wire.mimeType != spec.expected_mime_type:
        raise TransportPermanentError("Drive stored-file metadata does not match authority")
    if wire.mimeType.startswith(_GOOGLE_NATIVE_MIME_PREFIX):
        raise UnsupportedRepresentationError("raw stored-file representation requires a stored file")
    if not wire.capabilities.canDownload:
        raise UnsupportedRepresentationError("Drive stored file is not downloadable")
    size: int | None = None
    if wire.size is not None:
        try:
            size = int(wire.size)
        except ValueError as exc:
            raise TransportPermanentError("Drive stored-file size is invalid") from exc
        if size < 0 or str(size) != wire.size:
            raise TransportPermanentError("Drive stored-file size is not canonical")
    checksum = wire.sha256Checksum
    if checksum is not None and re.fullmatch(r"[0-9A-Fa-f]{64}", checksum) is None:
        raise TransportPermanentError("Drive stored-file SHA-256 is invalid")
    return size, checksum.lower() if checksum is not None else None


def _parse_modified_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TransportPermanentError("Drive metadata contains an invalid modified time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TransportPermanentError("Drive metadata modified time must be timezone-aware")
    return parsed


def _metadata_to_observation(raw: object) -> SourceObservation:
    try:
        wire = _DriveMetadataWire.model_validate(raw, strict=True)
        version = int(wire.version)
    except (ValidationError, ValueError) as exc:
        raise TransportPermanentError("Drive metadata failed strict validation") from exc
    if version < 0 or str(version) != wire.version:
        raise TransportPermanentError("Drive metadata version is not canonical")
    if not wire.parents:
        raise TransportPermanentError("Drive metadata contains no parent identity")
    return SourceObservation(
        object_id=wire.id,
        name=wire.name,
        mime_type=wire.mimeType,
        version=version,
        modified_time=_parse_modified_time(wire.modifiedTime),
        parent_ids=tuple(sorted(wire.parents)),
        trashed=wire.trashed,
        can_download=wire.capabilities.canDownload,
    )


def _google_id(value: str, *, label: str) -> str:
    if _GOOGLE_ID_RE.fullmatch(value) is None:
        raise TransportPermanentError(f"{label} is not a supported Google Drive identifier")
    return value


def _http_status(exc: BaseException) -> int | None:
    response = getattr(exc, "resp", None)
    value = getattr(response, "status", None)
    return value if type(value) is int else None


def _http_content(exc: BaseException) -> bytes:
    value = getattr(exc, "content", b"")
    return value if isinstance(value, bytes) else b""


def _rate_limited_403(exc: BaseException) -> bool:
    if _http_status(exc) != 403:
        return False
    try:
        payload = json.loads(_http_content(exc).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(payload, dict):
        return False
    error = payload.get("error")
    if not isinstance(error, dict):
        return False
    reasons: set[str] = set()
    for key in ("errors", "details"):
        values = error.get(key, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if isinstance(item, dict) and isinstance(item.get("reason"), str):
                reasons.add(item["reason"])
    return bool(reasons & {"rateLimitExceeded", "userRateLimitExceeded"})


class GoogleDriveTransport:
    def __init__(
        self,
        *,
        drive_service: _DriveService,
        http_error_types: tuple[type[BaseException], ...],
        request_attempts: int = 3,
        request_timeout: float = 30.0,
        sleeper: Callable[[float], None] = time.sleep,
        network_error_types: tuple[type[BaseException], ...] = (OSError,),
        auth_error_types: tuple[type[BaseException], ...] = (),
        transport_version: str = "injected-client",
        auth_provenance: str = "injected-client",
    ) -> None:
        if type(request_attempts) is not int or request_attempts < 1:
            raise ValueError("request_attempts must be a positive integer")
        if request_timeout <= 0:
            raise ValueError("request_timeout must be positive")
        self._drive = drive_service
        self._http_error_types = http_error_types
        self._network_error_types = network_error_types
        self._auth_error_types = auth_error_types
        self._request_attempts = request_attempts
        self.request_timeout = request_timeout
        self._sleeper = sleeper
        self._provenance = TransportProvenance(
            transport_name="google-drive-v3",
            transport_version=transport_version,
            auth_provenance=auth_provenance,
        )

    @property
    def provenance(self) -> TransportProvenance:
        return self._provenance

    @classmethod
    def from_application_default(
        cls,
        *,
        request_attempts: int = 3,
        request_timeout: float = 30.0,
    ) -> GoogleDriveTransport:
        try:
            import google.auth
            from google.auth.exceptions import DefaultCredentialsError, GoogleAuthError
            from google.auth.exceptions import TransportError as GoogleTransportError
            import httplib2  # type: ignore[import-untyped]
            from httplib2 import HttpLib2Error
            from google_auth_httplib2 import AuthorizedHttp  # type: ignore[import-untyped]
            from googleapiclient.discovery import build  # type: ignore[import-untyped]
            from googleapiclient.errors import HttpError  # type: ignore[import-untyped]
        except ImportError:
            raise TransportAuthError("Google Drive support is not installed") from None
        try:
            credentials, _ = google.auth.default(scopes=[DRIVE_READONLY_SCOPE])
            http = AuthorizedHttp(credentials, http=httplib2.Http(timeout=request_timeout))
            drive_service = build("drive", "v3", http=http, cache_discovery=False)
        except (DefaultCredentialsError, GoogleAuthError, OSError):
            raise TransportAuthError("Google application-default read credentials are unavailable") from None
        try:
            client_version = version("google-api-python-client")
        except PackageNotFoundError:
            client_version = "unknown"
        if "service_account" in type(credentials).__module__:
            auth_provenance = "adc:service-account"
        elif "identity_pool" in type(credentials).__module__:
            auth_provenance = "adc:workload-identity"
        else:
            auth_provenance = "adc:authorized-user"
        return cls(
            drive_service=drive_service,
            http_error_types=(HttpError,),
            network_error_types=(OSError, HttpLib2Error, GoogleTransportError),
            auth_error_types=(GoogleAuthError,),
            request_attempts=request_attempts,
            request_timeout=request_timeout,
            transport_version=client_version,
            auth_provenance=auth_provenance,
        )

    def _execute(self, factory: Callable[[], _Request]) -> object:
        last_transient: BaseException | None = None
        for attempt in range(self._request_attempts):
            try:
                return factory().execute()
            except self._network_error_types as exc:
                last_transient = exc
                if attempt + 1 < self._request_attempts:
                    self._sleeper(random.uniform(0.0, float(2**attempt)))
                    continue
                break
            except self._auth_error_types:
                raise TransportAuthError("Google credential refresh failed") from None
            except self._http_error_types as exc:
                status = _http_status(exc)
                transient = status in _TRANSIENT_STATUSES or _rate_limited_403(exc)
                if transient:
                    last_transient = exc
                    if attempt + 1 < self._request_attempts:
                        self._sleeper(random.uniform(0.0, float(2**attempt)))
                        continue
                    break
                if status == 401:
                    raise TransportAuthError("Google source request was not authenticated") from None
                if status == 403:
                    raise TransportPermissionError("Google source request was not permitted") from None
                if status == 404:
                    raise TransportNotFoundError("Google source object was not found") from None
                raise TransportPermanentError("Google source request failed permanently") from None
        assert last_transient is not None
        raise TransportTransientError("Google source request exhausted transient retries") from None

    def observe(self, spec: AuthorityObjectSpec) -> SourceObservation:
        if spec.provider != "google_drive":
            raise TransportPermanentError("Google Drive transport received a different provider")
        object_id = _google_id(spec.object_id, label="object ID")
        raw = self._execute(
            lambda: self._drive.files().get(
                fileId=object_id,
                fields=DRIVE_METADATA_FIELDS,
                supportsAllDrives=True,
            )
        )
        return _metadata_to_observation(raw)

    def read(self, spec: AuthorityObjectSpec) -> SourceContent:
        if spec.provider != "google_drive":
            raise TransportPermanentError("Google Drive transport received a different provider")
        object_id = _google_id(spec.object_id, label="object ID")
        if spec.representation_schema == GOOGLE_DOC_MARKDOWN_REPRESENTATION:
            if spec.expected_mime_type != _GOOGLE_DOC_MIME:
                raise UnsupportedRepresentationError("Markdown export requires a native Google Doc")
            raw = self._execute(
                lambda: self._drive.files().export(fileId=object_id, mimeType=_MARKDOWN_MIME)
            )
            if type(raw) is not bytes:
                raise TransportPermanentError("Drive Markdown export did not return bytes")
            return SourceContent(representation_schema=GOOGLE_DOC_MARKDOWN_REPRESENTATION, data=raw)
        if spec.representation_schema == GOOGLE_DRIVE_FILE_DOWNLOAD_REPRESENTATION:
            metadata = self._execute(
                lambda: self._drive.files().get(
                    fileId=object_id,
                    fields=_RAW_DOWNLOAD_FIELDS,
                    supportsAllDrives=True,
                )
            )
            expected_size, expected_sha256 = _raw_download_contract(metadata, spec)
            raw = self._execute(lambda: self._drive.files().get_media(fileId=object_id))
            if type(raw) is not bytes:
                raise TransportPermanentError("Drive stored-file download did not return bytes")
            if expected_size is not None and len(raw) != expected_size:
                raise TransportPermanentError("Drive stored-file size did not match downloaded bytes")
            if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
                raise TransportPermanentError("Drive stored-file SHA-256 did not match downloaded bytes")
            return SourceContent(
                representation_schema=GOOGLE_DRIVE_FILE_DOWNLOAD_REPRESENTATION, data=raw
            )
        raise UnsupportedRepresentationError("Google source representation schema is unsupported")

    def list_members(self, parent_id: str) -> tuple[SourceObservation, ...]:
        parent = _google_id(parent_id, label="parent ID")
        observations: list[SourceObservation] = []
        page_token: str | None = None
        while True:
            kwargs: dict[str, object] = {
                "q": f"'{parent}' in parents and trashed = false",
                "fields": f"nextPageToken,files({DRIVE_METADATA_FIELDS})",
                "supportsAllDrives": True,
                "includeItemsFromAllDrives": True,
                "pageSize": 1000,
            }
            if page_token is not None:
                kwargs["pageToken"] = page_token

            def request() -> _Request:
                return self._drive.files().list(**kwargs)

            raw = self._execute(request)
            try:
                wire = _DriveListWire.model_validate(raw, strict=True)
            except ValidationError as exc:
                raise TransportPermanentError("Drive membership response failed strict validation") from exc
            observations.extend(
                _metadata_to_observation(item.model_dump(mode="python")) for item in wire.files
            )
            page_token = wire.nextPageToken
            if page_token is None:
                break
        return tuple(sorted(observations, key=lambda item: item.object_id))
