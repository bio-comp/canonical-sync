from __future__ import annotations

import copy
import tomllib
from pathlib import Path

import pytest

from canonical_sync.domain import AuthorityObjectSpec
from canonical_sync.errors import (
    TransportAuthError,
    TransportNotFoundError,
    TransportPermissionError,
    TransportPermanentError,
    TransportTransientError,
    UnsupportedRepresentationError,
)
from canonical_sync.google_drive import (
    DRIVE_METADATA_FIELDS,
    DRIVE_READONLY_SCOPE,
    GOOGLE_DOC_MARKDOWN_REPRESENTATION,
    GoogleDriveTransport,
)


class FakeHttpError(Exception):
    def __init__(self, status: int, content: bytes = b"") -> None:
        super().__init__(f"provider error {status}: {content!r}")
        self.resp = type("Resp", (), {"status": status})()
        self.content = content


class Request:
    def __init__(self, value=None, error: BaseException | None = None) -> None:
        self.value = value
        self.error = error

    def execute(self):
        if self.error is not None:
            raise self.error
        return copy.deepcopy(self.value)


class Resource:
    def __init__(self, *, gets=(), exports=(), lists=()) -> None:
        self.get_values = list(gets)
        self.export_values = list(exports)
        self.list_values = list(lists)
        self.get_calls: list[dict[str, object]] = []
        self.export_calls: list[dict[str, object]] = []
        self.list_calls: list[dict[str, object]] = []

    @staticmethod
    def _request(values: list[object]):
        value = values.pop(0)
        if isinstance(value, BaseException):
            return Request(error=value)
        return Request(value=value)

    def get(self, **kwargs):
        self.get_calls.append(kwargs)
        return self._request(self.get_values)

    def export(self, **kwargs):
        self.export_calls.append(kwargs)
        return self._request(self.export_values)

    def list(self, **kwargs):
        self.list_calls.append(kwargs)
        return self._request(self.list_values)


class DriveService:
    def __init__(self, resource: Resource) -> None:
        self.resource = resource

    def files(self):
        return self.resource


def metadata(*, version: str = "7", object_id: str = "object-001", name: str = "README.md"):
    return {
        "id": object_id,
        "name": name,
        "mimeType": "application/vnd.google-apps.document",
        "version": version,
        "modifiedTime": "2026-10-26T12:00:00.000Z",
        "parents": ["parent-001"],
        "trashed": False,
        "capabilities": {"canDownload": True},
    }


def spec(*, representation: str = GOOGLE_DOC_MARKDOWN_REPRESENTATION) -> AuthorityObjectSpec:
    return AuthorityObjectSpec(
        logical_path="README.md",
        provider="google_drive",
        object_id="object-001",
        expected_name="README.md",
        expected_mime_type="application/vnd.google-apps.document",
        expected_parent_id="parent-001",
        representation_schema=representation,
    )


def transport(*, gets=(), exports=(), lists=(), attempts: int = 2):
    resource = Resource(gets=gets, exports=exports, lists=lists)
    value = GoogleDriveTransport(
        drive_service=DriveService(resource),
        http_error_types=(FakeHttpError,),
        request_attempts=attempts,
        sleeper=lambda _: None,
    )
    return value, resource


def test_exact_readonly_scope_metadata_and_markdown_export_requests() -> None:
    markdown = b"# Heading\n\nBody\n"
    value, resource = transport(gets=[metadata()], exports=[markdown])
    observed = value.observe(spec())
    acquired = value.read(spec())

    assert DRIVE_READONLY_SCOPE == "https://www.googleapis.com/auth/drive.readonly"
    assert observed.version == 7
    assert resource.get_calls == [{
        "fileId": "object-001",
        "fields": DRIVE_METADATA_FIELDS,
        "supportsAllDrives": True,
    }]
    assert resource.export_calls == [{"fileId": "object-001", "mimeType": "text/markdown"}]
    assert acquired.representation_schema == GOOGLE_DOC_MARKDOWN_REPRESENTATION
    assert acquired.data == markdown


def test_export_bytes_are_used_exactly_without_normalization() -> None:
    markdown = b"# Heading\r\n\r\n- item  \n"
    value, _ = transport(exports=[markdown])
    assert value.read(spec()).data == markdown


def test_unsupported_representation_and_nonbytes_export_fail_closed() -> None:
    value, resource = transport(exports=[])
    with pytest.raises(UnsupportedRepresentationError, match="representation"):
        value.read(spec(representation="other-v1"))
    assert resource.export_calls == []

    value, _ = transport(exports=["not-bytes"])
    with pytest.raises(TransportPermanentError, match="bytes"):
        value.read(spec())


def test_malformed_metadata_fails_without_raw_provider_body() -> None:
    value, _ = transport(gets=[metadata(version="not-an-int")])
    with pytest.raises(TransportPermanentError, match="metadata"):
        value.observe(spec())


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, b"SECRET auth", TransportAuthError),
        (403, b"SECRET forbidden", TransportPermissionError),
        (404, b"SECRET absent", TransportNotFoundError),
        (400, b"SECRET bad request", TransportPermanentError),
    ],
)
def test_nonretryable_http_errors_are_typed_and_sanitized(
    status: int, body: bytes, expected: type[Exception]
) -> None:
    value, _ = transport(gets=[FakeHttpError(status, body)])
    with pytest.raises(expected) as caught:
        value.observe(spec())
    assert "SECRET" not in str(caught.value)


def test_transient_http_retries_boundedly_and_sanitizes_failure() -> None:
    value, resource = transport(
        gets=[FakeHttpError(503, b"SECRET first"), FakeHttpError(503, b"SECRET second")]
    )
    with pytest.raises(TransportTransientError) as caught:
        value.observe(spec())
    assert len(resource.get_calls) == 2
    assert "SECRET" not in str(caught.value)


def test_rate_limit_403_is_transient_but_other_403_is_permission() -> None:
    rate = b'{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}'
    value, resource = transport(gets=[FakeHttpError(403, rate), metadata()])
    assert value.observe(spec()).version == 7
    assert len(resource.get_calls) == 2


def test_exact_membership_listing_handles_pagination() -> None:
    first_page = {
        "files": [metadata(object_id="object-002", name="DECISIONS.md")],
        "nextPageToken": "next",
    }
    second_page = {"files": [metadata()], "nextPageToken": None}
    value, resource = transport(lists=[first_page, second_page])
    members = value.list_members("parent-001")
    assert [item.object_id for item in members] == ["object-001", "object-002"]
    assert len(resource.list_calls) == 2
    assert resource.list_calls[0]["q"] == "'parent-001' in parents and trashed = false"
    assert resource.list_calls[1]["pageToken"] == "next"


def test_package_google_clients_are_optional() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text())
    assert project["project"]["dependencies"] == ["pydantic==2.14.1"]
    assert project["project"]["optional-dependencies"]["drive"] == [
        "google-api-python-client==2.201.0",
        "google-auth==2.62.0",
    ]


def test_google_ids_reject_query_unsafe_values_before_network() -> None:
    value, resource = transport(gets=[], exports=[], lists=[])
    bad_spec = spec().__class__(
        logical_path="README.md",
        provider="google_drive",
        object_id="bad\' or trashed = false",
        expected_name="README.md",
        expected_mime_type="application/vnd.google-apps.document",
        expected_parent_id="parent-001",
        representation_schema=GOOGLE_DOC_MARKDOWN_REPRESENTATION,
    )
    with pytest.raises(TransportPermanentError, match="identifier"):
        value.observe(bad_spec)
    with pytest.raises(TransportPermanentError, match="identifier"):
        value.list_members("bad\' or trashed = false")
    assert resource.get_calls == []
    assert resource.list_calls == []


def test_rate_limit_403_parsing_is_not_whitespace_sensitive() -> None:
    rate = b'{"error": {"errors": [{"reason": "rateLimitExceeded"}]}}'
    value, resource = transport(gets=[FakeHttpError(403, rate), metadata()])
    assert value.observe(spec()).version == 7
    assert len(resource.get_calls) == 2


def test_network_failure_is_bounded_and_typed():
    value, resource = transport(gets=[TimeoutError('FAKE_NETWORK_SECRET')] * 2)
    with pytest.raises(TransportTransientError):
        value.observe(spec())
    assert len(resource.get_calls) == 2
