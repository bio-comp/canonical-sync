from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import ClassVar

from hypothesis import given, strategies as st

from canonical_sync.codec import (
    canonical_record_bytes,
    canonical_record_hash,
    parse_canonical_record,
)
from canonical_sync.records import StrictFrozenRecord


class FuzzSubItem(StrictFrozenRecord):
    key: str
    weight: int


class FuzzCodecRecord(StrictFrozenRecord):
    canonical_identity_domain: ClassVar[str] = "canonical-sync.test-fuzz-codec"
    canonical_identity_version: ClassVar[int] = 1

    schema_version: int = 1
    name: str
    count: int
    active: bool
    tags: tuple[str, ...]
    sub: FuzzSubItem | None = None
    timestamp: datetime


def _check_keys_sorted(raw_json: object) -> None:
    if isinstance(raw_json, dict):
        keys = list(raw_json.keys())
        assert keys == sorted(keys), f"Keys not sorted: {keys}"
        for value in raw_json.values():
            _check_keys_sorted(value)
    elif isinstance(raw_json, list):
        for item in raw_json:
            _check_keys_sorted(item)


# Generate valid UTC microsecond datetimes
utc_datetimes = st.datetimes(
    min_value=datetime(1970, 1, 1),
    max_value=datetime(2100, 1, 1),
    timezones=st.just(timezone.utc),
)

valid_strings = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",)),  # avoid surrogate pairs
    max_size=50,
)


@st.composite
def fuzz_codec_records(draw: st.DrawFn) -> FuzzCodecRecord:
    name = draw(valid_strings)
    count = draw(st.integers(min_value=-1_000_000, max_value=1_000_000))
    active = draw(st.booleans())
    tags = tuple(draw(st.lists(valid_strings, max_size=5)))
    has_sub = draw(st.booleans())
    sub = (
        FuzzSubItem(
            key=draw(valid_strings),
            weight=draw(st.integers(min_value=-1000, max_value=1000)),
        )
        if has_sub
        else None
    )
    timestamp = draw(utc_datetimes)
    return FuzzCodecRecord(
        name=name,
        count=count,
        active=active,
        tags=tags,
        sub=sub,
        timestamp=timestamp,
    )


@given(record=fuzz_codec_records())
def test_fuzz_codec_roundtrip_bijectivity(record: FuzzCodecRecord) -> None:
    data = canonical_record_bytes(record)

    # 1. UTF-8 valid and no BOM
    assert not data.startswith(b"\xef\xbb\xbf")
    decoded = data.decode("utf-8")

    # 2. No trailing newline or carriage return
    assert not data.endswith(b"\n")
    assert not data.endswith(b"\r")

    # 3. Compact strict separators (no whitespace around ':' or ',')
    # Check at JSON token level
    parsed_json = json.loads(decoded)
    assert json.dumps(parsed_json, ensure_ascii=False, sort_keys=True, separators=(",", ":")) == decoded

    # 4. Keys sorted lexicographically
    _check_keys_sorted(parsed_json)

    # 5. Roundtrip bijectivity
    roundtripped = parse_canonical_record(data, FuzzCodecRecord)
    assert roundtripped == record

    # 6. Hash determinism
    h1 = canonical_record_hash(record)
    h2 = canonical_record_hash(roundtripped)
    assert h1 == h2
    assert len(h1) == 64


@given(record=fuzz_codec_records())
def test_fuzz_codec_rejects_non_canonical_formatting(record: FuzzCodecRecord) -> None:
    data = canonical_record_bytes(record)

    # Adding a trailing newline must fail non-canonical check
    with_newline = data + b"\n"
    import pytest

    with pytest.raises(ValueError, match="not canonical JSON"):
        parse_canonical_record(with_newline, FuzzCodecRecord)
