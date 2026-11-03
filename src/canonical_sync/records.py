from __future__ import annotations

import re
import hashlib
from urllib.parse import urlsplit
import unicodedata
from collections.abc import Iterable
from datetime import datetime
from pathlib import PurePosixPath
from typing import ClassVar, Literal, Self

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ILLEGAL_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_STEM_RE = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$", re.IGNORECASE
)
# Code points stripped by Git's next_hfs_char() under core.protectHFS
_HFS_IGNORABLE_CHARS = frozenset(
    {
        *(chr(cp) for cp in range(0x200C, 0x2010)),  # U+200C..U+200F
        *(chr(cp) for cp in range(0x202A, 0x202F)),  # U+202A..U+202E
        *(chr(cp) for cp in range(0x206A, 0x2070)),  # U+206A..U+206F
        "\ufeff",  # U+FEFF ZERO WIDTH NO-BREAK SPACE
    }
)
# Reserved Git metadata directory/file names under core.protectHFS and core.protectNTFS
_GIT_METADATA_NAMES = frozenset({".git", "git~1"})


class StrictFrozenRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    @field_validator("schema_version", mode="before", check_fields=False)
    @classmethod
    def _reject_non_exact_int_schema_version(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema_version must be an exact integer")
        return value


def _nonempty_trimmed(value: str, *, label: str) -> str:
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError(f"{label} must be non-empty, trimmed, and contain no control characters")
    return value


def _portable_component_key(part: str) -> str:
    if part in {"", ".", ".."}:
        raise ValueError("logical path contains an unsafe component")
    if any(ord(character) <= 0x1F or ord(character) == 0x7F for character in part):
        raise ValueError("logical path contains an ASCII control character")
    if any(character in _WINDOWS_ILLEGAL_CHARS for character in part):
        raise ValueError("logical path contains a portable-illegal character")
    hfs_stripped = "".join(ch for ch in part if ch not in _HFS_IGNORABLE_CHARS)
    nfc_stripped = "".join(
        ch for ch in unicodedata.normalize("NFC", part) if ch not in _HFS_IGNORABLE_CHARS
    )
    for candidate in (part, hfs_stripped, nfc_stripped):
        if candidate in {"", ".", ".."}:
            raise ValueError("logical path contains an unsafe component")
        if candidate.endswith((" ", ".")):
            raise ValueError("logical path component has an unsafe trailing character")
        if candidate.rstrip(" .").casefold() in _GIT_METADATA_NAMES:
            raise ValueError("logical path contains a protected Git metadata component")
        stem = candidate.split(".", 1)[0].rstrip(" ")
        if _WINDOWS_RESERVED_STEM_RE.fullmatch(stem):
            raise ValueError("logical path uses a reserved portable filename")
    return nfc_stripped.casefold()


def _portable_path_parts(value: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _nonempty_trimmed(value, label="logical path")
    if "\\" in value:
        raise ValueError("logical path must use POSIX separators")
    raw_parts = tuple(value.split("/"))
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.parts != raw_parts
        or path.as_posix() != value
    ):
        raise ValueError("logical path must be a canonical relative POSIX path")
    key_parts = tuple(_portable_component_key(part) for part in raw_parts)
    return raw_parts, key_parts


def _portable_path_key(value: str) -> str:
    _, key_parts = _portable_path_parts(value)
    return "/".join(key_parts)


def _safe_logical_path(value: str) -> str:
    _portable_path_key(value)
    return value


def _sha256(value: str) -> str:
    if _SHA256_RE.fullmatch(value) is None:
        raise ValueError("value must be a lowercase SHA-256 hex digest")
    return value


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("datetime must be timezone-aware")
    return value


class AuthorityObjectSpecRecord(StrictFrozenRecord):
    logical_path: str
    provider: str
    object_id: str
    expected_name: str
    expected_mime_type: str
    expected_parent_id: str | None = None
    representation_schema: str

    @field_validator("logical_path")
    @classmethod
    def validate_logical_path(cls, value: str) -> str:
        return _safe_logical_path(value)

    @field_validator(
        "provider",
        "object_id",
        "expected_name",
        "expected_mime_type",
        "representation_schema",
    )
    @classmethod
    def validate_required_strings(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="authority field")

    @field_validator("expected_parent_id")
    @classmethod
    def validate_parent(cls, value: str | None) -> str | None:
        if value is not None:
            return _nonempty_trimmed(value, label="parent ID")
        return value


class ExactMembershipSpecRecord(StrictFrozenRecord):
    parent_id: str
    expected_child_ids: tuple[str, ...]

    @field_validator("parent_id")
    @classmethod
    def validate_parent(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="membership parent ID")

    @field_validator("expected_child_ids")
    @classmethod
    def validate_children(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("exact membership requires at least one child")
        normalized = tuple(sorted(_nonempty_trimmed(item, label="child ID") for item in value))
        if len(normalized) != len(set(normalized)):
            raise ValueError("exact membership child IDs must be unique")
        return normalized


def _validate_no_path_hierarchy_collisions(paths: Iterable[str]) -> None:
    seen_files: dict[tuple[str, ...], str] = {}
    for raw_path in sorted(paths):
        _, key_parts = _portable_path_parts(raw_path)
        seen_files.setdefault(key_parts, raw_path)
    for key_parts, raw_path in seen_files.items():
        for depth in range(1, len(key_parts)):
            ancestor_key = key_parts[:depth]
            if ancestor_key in seen_files:
                ancestor_path = seen_files[ancestor_key]
                raise ValueError(
                    f"path hierarchy collision between '{ancestor_path}' and '{raw_path}'"
                )


def _validate_path_inventory(
    paths: Iterable[str],
    *,
    collision_message: str = "paths collide portably",
) -> None:
    seen_files: dict[tuple[str, ...], str] = {}
    seen_dirs: dict[tuple[str, ...], tuple[tuple[str, ...], str]] = {}
    for raw_path in paths:
        raw_parts, key_parts = _portable_path_parts(raw_path)
        if key_parts in seen_files:
            raise ValueError(collision_message)
        seen_files[key_parts] = raw_path
        for depth in range(1, len(raw_parts)):
            dir_key = key_parts[:depth]
            dir_raw = raw_parts[:depth]
            if dir_key in seen_dirs:
                existing_raw, existing_path = seen_dirs[dir_key]
                if existing_raw != dir_raw:
                    raise ValueError(
                        f"directory prefix alias collision between '{'/'.join(existing_raw)}' "
                        f"in '{existing_path}' and '{'/'.join(dir_raw)}' in '{raw_path}'"
                    )
            else:
                seen_dirs[dir_key] = (dir_raw, raw_path)
    for key_parts, raw_path in seen_files.items():
        for depth in range(1, len(key_parts)):
            ancestor_key = key_parts[:depth]
            if ancestor_key in seen_files:
                ancestor_path = seen_files[ancestor_key]
                raise ValueError(
                    f"path hierarchy collision between '{ancestor_path}' and '{raw_path}'"
                )


class _BaseAuthoritySpecRecord(StrictFrozenRecord):
    objects: tuple[AuthorityObjectSpecRecord, ...]
    memberships: tuple[ExactMembershipSpecRecord, ...] = ()

    @field_validator("objects")
    @classmethod
    def normalize_objects(
        cls, value: tuple[AuthorityObjectSpecRecord, ...]
    ) -> tuple[AuthorityObjectSpecRecord, ...]:
        if not value:
            label = "authority profile" if "Profile" in cls.__name__ else "authority specification"
            raise ValueError(f"{label} requires at least one object")
        ordered = tuple(sorted(value, key=lambda item: item.logical_path))
        _validate_path_inventory(
            (item.logical_path for item in ordered),
            collision_message="authority logical paths collide portably",
        )
        object_ids = tuple(item.object_id for item in ordered)
        if len(object_ids) != len(set(object_ids)):
            raise ValueError("authority object IDs must be unique")
        return ordered

    @field_validator("memberships")
    @classmethod
    def normalize_memberships(
        cls, value: tuple[ExactMembershipSpecRecord, ...]
    ) -> tuple[ExactMembershipSpecRecord, ...]:
        ordered = tuple(sorted(value, key=lambda item: item.parent_id))
        parents = tuple(item.parent_id for item in ordered)
        if len(parents) != len(set(parents)):
            raise ValueError("membership parents must be unique")
        return ordered

    @model_validator(mode="after")
    def validate_membership_coherence(self) -> Self:
        by_id = {item.object_id: item for item in self.objects}
        for membership in self.memberships:
            for child_id in membership.expected_child_ids:
                child = by_id.get(child_id)
                if child is None:
                    raise ValueError("exact membership references an undeclared authority object")
                if child.expected_parent_id != membership.parent_id:
                    raise ValueError("exact membership parent conflicts with object authority")
        return self


class AuthorityProfileRecord(_BaseAuthoritySpecRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.authority-profile"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["authority_profile"] = "authority_profile"
    schema_version: Literal[1] = 1
    profile_name: str

    @field_validator("profile_name")
    @classmethod
    def validate_profile_name(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="profile name")


class AuthoritySpecificationRecord(_BaseAuthoritySpecRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.authority-specification"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["authority_specification"] = "authority_specification"
    schema_version: Literal[1] = 1


class SemanticEntryRecord(StrictFrozenRecord):
    logical_path: str
    representation_schema: str
    content_sha256: str

    @field_validator("logical_path")
    @classmethod
    def validate_logical_path(cls, value: str) -> str:
        return _safe_logical_path(value)

    @field_validator("representation_schema")
    @classmethod
    def validate_representation(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="representation schema")

    @field_validator("content_sha256")
    @classmethod
    def validate_content_hash(cls, value: str) -> str:
        return _sha256(value)


class SnapshotStateRecord(StrictFrozenRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.source-state"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["snapshot_state"] = "snapshot_state"
    schema_version: Literal[2] = 2
    authority_spec_sha256: str
    entries: tuple[SemanticEntryRecord, ...]

    @field_validator("authority_spec_sha256")
    @classmethod
    def validate_authority_spec_hash(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("entries")
    @classmethod
    def normalize_entries(
        cls, value: tuple[SemanticEntryRecord, ...]
    ) -> tuple[SemanticEntryRecord, ...]:
        if not value:
            raise ValueError("snapshot state requires at least one semantic entry")
        ordered = tuple(sorted(value, key=lambda item: item.logical_path))
        _validate_path_inventory(
            (item.logical_path for item in ordered),
            collision_message="snapshot logical paths collide portably",
        )
        return ordered


class SourceObservationRecord(StrictFrozenRecord):
    logical_path: str
    object_id: str
    name: str
    mime_type: str
    version: int
    modified_time: datetime
    parent_ids: tuple[str, ...]
    trashed: bool
    can_download: bool
    representation_schema: str
    content_sha256: str

    @field_validator("logical_path")
    @classmethod
    def validate_logical_path(cls, value: str) -> str:
        return _safe_logical_path(value)

    @field_validator("object_id", "name", "mime_type", "representation_schema")
    @classmethod
    def validate_strings(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="source observation field")

    @field_validator("version")
    @classmethod
    def validate_version(cls, value: int) -> int:
        if value < 0:
            raise ValueError("source version must be nonnegative")
        return value

    @field_validator("modified_time")
    @classmethod
    def validate_modified_time(cls, value: datetime) -> datetime:
        return _aware(value)

    @field_validator("parent_ids")
    @classmethod
    def validate_parents(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted(_nonempty_trimmed(item, label="parent ID") for item in value))
        if len(normalized) != len(set(normalized)):
            raise ValueError("parent IDs must be unique")
        return normalized

    @field_validator("content_sha256")
    @classmethod
    def validate_content_hash(cls, value: str) -> str:
        return _sha256(value)


class AcquisitionProvenanceRecord(StrictFrozenRecord):
    runner_name: str
    runner_version: str
    python_implementation: str
    python_version: str
    transport_name: str
    transport_version: str
    auth_provenance: str

    @field_validator(
        "runner_name",
        "runner_version",
        "python_implementation",
        "python_version",
        "transport_name",
        "transport_version",
        "auth_provenance",
    )
    @classmethod
    def validate_provenance_strings(cls, value: str) -> str:
        return _nonempty_trimmed(value, label="acquisition provenance field")


class SnapshotObservationRecord(StrictFrozenRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.observation"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["snapshot_observation"] = "snapshot_observation"
    schema_version: Literal[3] = 3
    snapshot_state_sha256: str
    authority_spec_sha256: str
    acquired_at: datetime
    attempt_count: int
    provenance: AcquisitionProvenanceRecord
    sources: tuple[SourceObservationRecord, ...]

    @field_validator("snapshot_state_sha256", "authority_spec_sha256")
    @classmethod
    def validate_hashes(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("acquired_at")
    @classmethod
    def validate_acquired_at(cls, value: datetime) -> datetime:
        return _aware(value)

    @field_validator("attempt_count")
    @classmethod
    def validate_attempt_count(cls, value: int) -> int:
        if value < 1:
            raise ValueError("attempt count must be positive")
        return value

    @field_validator("sources")
    @classmethod
    def normalize_sources(
        cls, value: tuple[SourceObservationRecord, ...]
    ) -> tuple[SourceObservationRecord, ...]:
        if not value:
            raise ValueError("snapshot observation requires at least one source")
        ordered = tuple(sorted(value, key=lambda item: item.logical_path))
        _validate_path_inventory(
            (item.logical_path for item in ordered),
            collision_message="source observations must have unique logical paths",
        )
        return ordered

    @model_validator(mode="after")
    def validate_source_hashes(self) -> Self:
        for source in self.sources:
            _sha256(source.content_sha256)
        return self


class AcquisitionReceiptRecord(StrictFrozenRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.acquisition-receipt"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["acquisition_receipt"] = "acquisition_receipt"
    schema_version: Literal[4] = 4
    started_at: datetime
    ended_at: datetime
    authority_spec_sha256: str
    provenance: AcquisitionProvenanceRecord
    transaction_attempt_count: int
    status: Literal["success", "failed"]
    error_code: str | None = None
    snapshot_state_sha256: str | None = None
    snapshot_observation_sha256: str | None = None

    @field_validator("started_at", "ended_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _aware(value)

    @field_validator("authority_spec_sha256")
    @classmethod
    def validate_authority_hash(cls, value: str) -> str:
        return _sha256(value)

    @field_validator("snapshot_state_sha256", "snapshot_observation_sha256")
    @classmethod
    def validate_optional_hash(cls, value: str | None) -> str | None:
        if value is not None:
            return _sha256(value)
        return value

    @field_validator("transaction_attempt_count")
    @classmethod
    def validate_attempt_count(cls, value: int) -> int:
        if value < 0:
            raise ValueError("transaction attempt count must be nonnegative")
        return value

    @field_validator("error_code")
    @classmethod
    def validate_error_code(cls, value: str | None) -> str | None:
        if value is not None:
            return _nonempty_trimmed(value, label="error code")
        return value

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.ended_at < self.started_at:
            raise ValueError("acquisition receipt ended_at precedes started_at")
        if self.status == "success":
            if self.transaction_attempt_count < 1:
                raise ValueError("successful acquisition requires at least one transaction attempt")
            if self.error_code is not None:
                raise ValueError("successful acquisition cannot contain an error code")
            if self.snapshot_state_sha256 is None or self.snapshot_observation_sha256 is None:
                raise ValueError("successful acquisition requires state and observation identities")
        else:
            if self.error_code is None:
                raise ValueError("failed acquisition requires a structured error code")
            if self.snapshot_state_sha256 is not None or self.snapshot_observation_sha256 is not None:
                raise ValueError("failed acquisition cannot claim successful snapshot identities")
        return self


def safe_remote_identity(value: str) -> str:
    """Retain repository identity, never transport credentials or local paths."""
    _nonempty_trimmed(value, label="publication remote")
    if re.fullmatch(r"opaque-sha256:[0-9a-f]{64}", value):
        return value
    locator = value
    if re.fullmatch(r"git@[^/:]+:[^?#]+", value):
        locator = "ssh://" + value.replace(":", "/", 1)
    try:
        parsed = urlsplit(locator)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        host = None
    if (host and parsed.scheme in {"https", "ssh"}
            and re.fullmatch(r"[A-Za-z0-9.-]+", host)
            and re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path)):
        endpoint = host.lower() + (f":{port}" if port is not None else "")
        return f"https://{endpoint}{parsed.path}"
    return "opaque-sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class GitPublicationReceiptRecord(StrictFrozenRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.git-publication-receipt"
    canonical_identity_version: ClassVar[int] = 1
    record_type: Literal["git_publication_receipt"] = "git_publication_receipt"
    schema_version: Literal[3] = 3
    status: Literal["published", "unchanged"]
    remote: str
    remote_ref: str
    expected_base_commit: str | None = None
    resulting_commit: str
    git_tree_oid: str
    publication_tree_sha256: str
    verified_remote_commit: str
    readback_verified: bool
    fast_forward_only: bool

    @field_validator("remote")
    @classmethod
    def validate_remote(cls, value: str) -> str:
        return safe_remote_identity(value)

    @field_validator("remote_ref")
    @classmethod
    def validate_remote_ref(cls, value: str) -> str:
        value = _nonempty_trimmed(value, label="remote ref")
        if not value.startswith("refs/heads/"):
            raise ValueError("publication remote ref must be a branch ref")
        return value

    @field_validator(
        "expected_base_commit",
        "resulting_commit",
        "git_tree_oid",
        "verified_remote_commit",
    )
    @classmethod
    def validate_git_oid(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value) is None:
            raise ValueError("Git object IDs must be lowercase 40- or 64-character hex")
        return value

    @field_validator("publication_tree_sha256")
    @classmethod
    def validate_tree_hash(cls, value: str) -> str:
        return _sha256(value)

    @model_validator(mode="after")
    def validate_verified_result(self) -> Self:
        if self.resulting_commit != self.verified_remote_commit:
            raise ValueError("publication receipt remote verification does not match result")
        if not self.readback_verified or not self.fast_forward_only:
            raise ValueError("publication receipt requires verified readback and fast-forward-only semantics")
        if self.status == "unchanged" and self.expected_base_commit != self.resulting_commit:
            raise ValueError("unchanged publication must preserve the expected remote base")
        return self
