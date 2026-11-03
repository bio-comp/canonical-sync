from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from typing import TypeVar

from pydantic import BaseModel

_RecordT = TypeVar("_RecordT", bound=BaseModel)

CANONICAL_IDENTITY_PROTOCOL_VERSION = 1
_IDENTITY_MAGIC = b"canonical-sync-record-identity\x00"


def _require_pydantic_record(record: object) -> BaseModel:
    if not isinstance(record, BaseModel):
        raise TypeError("canonical durable records must be Pydantic BaseModel instances")
    return record


def _canonical_scalar(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, Enum):
        return _canonical_scalar(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("canonical datetime must be timezone-aware")
        normalized = value.astimezone(UTC)
        return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if isinstance(value, (tuple, list)):
        return [_canonical_scalar(item) for item in value]
    if isinstance(value, dict):
        if any(type(key) is not str for key in value):
            raise TypeError("canonical record mappings require string keys")
        return {key: _canonical_scalar(item) for key, item in value.items()}
    if isinstance(value, float):
        raise TypeError("canonical record identity does not support floating-point scalars")
    raise TypeError(f"unsupported canonical record scalar: {type(value).__name__}")


def canonical_record_bytes(record: BaseModel) -> bytes:
    """Return canonical UTF-8 JSON payload bytes with no trailing newline."""

    validated = _require_pydantic_record(record)
    normalized = _canonical_scalar(validated.model_dump(mode="python"))
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _identity_descriptor(record: BaseModel) -> tuple[str, int, int]:
    record_type = type(record)
    domain = getattr(record_type, "canonical_identity_domain", None)
    domain_version = getattr(record_type, "canonical_identity_version", None)
    schema_version = getattr(record, "schema_version", None)
    if type(domain) is not str or not domain or domain != domain.strip() or "\x00" in domain:
        raise TypeError("canonical record type must declare a valid canonical_identity_domain")
    if type(domain_version) is not int or domain_version < 1:
        raise TypeError("canonical record type must declare a positive canonical_identity_version")
    if type(schema_version) is not int or schema_version < 1:
        raise TypeError("canonical record must expose a positive integer schema_version")
    return domain, domain_version, schema_version


def _frame(value: bytes) -> bytes:
    return len(value).to_bytes(8, "big") + value


def canonical_identity_bytes(record: BaseModel) -> bytes:
    """Return the versioned, domain-separated bytes used for cryptographic identity."""

    validated = _require_pydantic_record(record)
    domain, domain_version, schema_version = _identity_descriptor(validated)
    payload = canonical_record_bytes(validated)
    return b"".join(
        (
            _IDENTITY_MAGIC,
            CANONICAL_IDENTITY_PROTOCOL_VERSION.to_bytes(4, "big"),
            _frame(domain.encode("utf-8")),
            domain_version.to_bytes(4, "big"),
            schema_version.to_bytes(4, "big"),
            _frame(payload),
        )
    )


def canonical_record_hash(record: BaseModel) -> str:
    return hashlib.sha256(canonical_identity_bytes(record)).hexdigest()


def parse_canonical_record(data: bytes, record_type: type[_RecordT]) -> _RecordT:
    if type(data) is not bytes:
        raise TypeError("canonical record input must be bytes")
    record = record_type.model_validate_json(data, strict=True)
    if canonical_record_bytes(record) != data:
        raise ValueError("record is valid but not canonical JSON")
    return record
