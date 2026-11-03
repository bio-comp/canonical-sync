from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from canonical_sync.codec import canonical_record_bytes, canonical_record_hash, parse_canonical_record
from canonical_sync.domain import profile_from_record
from canonical_sync.records import (
    AcquisitionProvenanceRecord,
    AuthorityObjectSpecRecord,
    AuthorityProfileRecord,
    ExactMembershipSpecRecord,
    SemanticEntryRecord,
    SnapshotObservationRecord,
    SnapshotStateRecord,
    SourceObservationRecord,
)

H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def object_spec(*, path: str = "README.md", object_id: str = "opaque-object-001") -> AuthorityObjectSpecRecord:
    return AuthorityObjectSpecRecord(
        logical_path=path,
        provider="google_drive",
        object_id=object_id,
        expected_name=path.rsplit("/", 1)[-1],
        expected_mime_type="application/vnd.google-apps.document",
        expected_parent_id="opaque-parent-001",
        representation_schema="test-representation-v1",
    )


def profile() -> AuthorityProfileRecord:
    return AuthorityProfileRecord(
        profile_name="test-profile",
        objects=(object_spec(), object_spec(path="DECISIONS.md", object_id="opaque-object-002")),
    )


def state(*, authority_hash: str = H1, first_content_hash: str = H2) -> SnapshotStateRecord:
    return SnapshotStateRecord(
        authority_spec_sha256=authority_hash,
        entries=(
            SemanticEntryRecord(
                logical_path="README.md",
                representation_schema="test-representation-v1",
                content_sha256=first_content_hash,
            ),
            SemanticEntryRecord(
                logical_path="DECISIONS.md",
                representation_schema="test-representation-v1",
                content_sha256=H3,
            ),
        ),
    )


def observation(*, snapshot_hash: str, version: int = 7, acquired_at: datetime = T0) -> SnapshotObservationRecord:
    return SnapshotObservationRecord(
        snapshot_state_sha256=snapshot_hash,
        authority_spec_sha256=H1,
        acquired_at=acquired_at,
        attempt_count=1,
        provenance=AcquisitionProvenanceRecord(
            runner_name="canonical-sync",
            runner_version="test",
            python_implementation="CPython",
            python_version="3.11.13",
            transport_name="fake-transport",
            transport_version="test-v1",
            auth_provenance="test-injected",
        ),
        sources=(
            SourceObservationRecord(
                logical_path="README.md",
                object_id="opaque-object-001",
                name="README.md",
                mime_type="application/vnd.google-apps.document",
                version=version,
                modified_time=T0,
                parent_ids=("opaque-parent-001",),
                trashed=False,
                can_download=True,
                representation_schema="test-representation-v1",
                content_sha256=H2,
            ),
        ),
    )


def test_strict_boundary_rejects_unknown_fields_and_type_coercion() -> None:
    with pytest.raises(ValidationError):
        AuthorityObjectSpecRecord.model_validate(object_spec().model_dump() | {"unexpected": True})
    with pytest.raises(ValidationError):
        SourceObservationRecord(
            logical_path="README.md",
            object_id="opaque-object-001",
            name="README.md",
            mime_type="application/vnd.google-apps.document",
            version="7",
            modified_time=T0,
            parent_ids=("opaque-parent-001",),
            trashed=False,
            can_download=True,
            representation_schema="test-representation-v1",
            content_sha256=H2,
        )


def test_profile_rejects_unsafe_duplicate_and_portably_colliding_paths() -> None:
    for bad in ("", "/absolute.md", "../escape.md", "Research/../escape.md", ".git/config"):
        with pytest.raises(ValidationError):
            object_spec(path=bad)

    with pytest.raises(ValidationError):
        AuthorityProfileRecord(profile_name="dup", objects=(object_spec(), object_spec()))

    with pytest.raises(ValidationError):
        AuthorityProfileRecord(
            profile_name="casefold",
            objects=(
                object_spec(path="Research/Foo.md", object_id="opaque-object-001"),
                object_spec(path="Research/foo.md", object_id="opaque-object-002"),
            ),
        )


def test_profile_converts_to_frozen_slotted_trusted_domain() -> None:
    trusted = profile_from_record(profile())
    assert trusted.profile_name == "test-profile"
    assert trusted.objects[0].logical_path == "DECISIONS.md"
    with pytest.raises((AttributeError, TypeError)):
        trusted.profile_name = "changed"  # type: ignore[misc]


def test_canonical_round_trip_is_byte_identical_and_noncanonical_json_is_rejected() -> None:
    value = state()
    encoded = canonical_record_bytes(value)
    assert parse_canonical_record(encoded, SnapshotStateRecord) == value
    assert canonical_record_bytes(parse_canonical_record(encoded, SnapshotStateRecord)) == encoded

    noncanonical = json.dumps(value.model_dump(mode="json"), indent=2, sort_keys=False).encode()
    assert noncanonical != encoded
    with pytest.raises(ValueError, match="canonical"):
        parse_canonical_record(noncanonical, SnapshotStateRecord)


def test_canonical_datetime_identity_normalizes_equivalent_instants() -> None:
    snapshot_hash = canonical_record_hash(state())
    first = observation(snapshot_hash=snapshot_hash, acquired_at=T0)
    equivalent = observation(
        snapshot_hash=snapshot_hash,
        acquired_at=T0.astimezone(timezone(timedelta(hours=-6))),
    )

    assert first.acquired_at != equivalent.acquired_at or first.acquired_at.utcoffset() != equivalent.acquired_at.utcoffset()
    assert canonical_record_bytes(first) == canonical_record_bytes(equivalent)
    assert canonical_record_hash(first) == canonical_record_hash(equivalent)


def test_profile_label_does_not_change_registered_authority_spec_identity() -> None:
    original = profile()
    renamed = original.model_copy(update={"profile_name": "renamed-profile"})

    assert profile_from_record(original).spec_sha256 == profile_from_record(renamed).spec_sha256


def test_semantic_state_identity_is_order_independent_but_content_and_authority_sensitive() -> None:
    first = state()
    reordered = SnapshotStateRecord(
        authority_spec_sha256=H1,
        entries=tuple(reversed(first.entries)),
    )
    content_changed = state(first_content_hash="4" * 64)
    authority_changed = state(authority_hash="5" * 64)

    assert first.entries == reordered.entries
    assert canonical_record_hash(first) == canonical_record_hash(reordered)
    assert canonical_record_hash(first) != canonical_record_hash(content_changed)
    assert canonical_record_hash(first) != canonical_record_hash(authority_changed)


def test_source_state_identity_binds_registered_object_identity_not_only_content() -> None:
    original_profile = profile()
    changed_profile = AuthorityProfileRecord(
        profile_name=original_profile.profile_name,
        objects=(
            object_spec(object_id="different-authoritative-object"),
            object_spec(path="DECISIONS.md", object_id="opaque-object-002"),
        ),
    )
    original_state = state(authority_hash=profile_from_record(original_profile).spec_sha256)
    changed_state = state(authority_hash=profile_from_record(changed_profile).spec_sha256)

    assert original_state.entries == changed_state.entries
    assert canonical_record_hash(original_state) != canonical_record_hash(changed_state)


def test_observation_identity_changes_for_metadata_only_churn_without_changing_semantic_state() -> None:
    semantic = state()
    semantic_hash = canonical_record_hash(semantic)
    first = observation(snapshot_hash=semantic_hash, version=7, acquired_at=T0)
    second = observation(
        snapshot_hash=semantic_hash,
        version=8,
        acquired_at=T0 + timedelta(minutes=5),
    )

    assert first.snapshot_state_sha256 == second.snapshot_state_sha256 == semantic_hash
    assert canonical_record_hash(first) != canonical_record_hash(second)


def test_hash_fields_are_lowercase_sha256_only() -> None:
    with pytest.raises(ValidationError):
        SemanticEntryRecord(
            logical_path="README.md",
            representation_schema="test-representation-v1",
            content_sha256="not-a-hash",
        )
    with pytest.raises(ValidationError):
        state(authority_hash="A" * 64)


@pytest.mark.parametrize(
    "bad",
    [
        "CON",
        "aux.txt",
        "Research/bad:name.md",
        "Research/trailing.",
        "Research/trailing ",
        "Research/control\x7f.md",
    ],
)
def test_profile_rejects_portably_unsafe_path_components(bad: str) -> None:
    with pytest.raises(ValidationError):
        object_spec(path=bad)


def test_profile_rejects_unicode_normalization_collisions() -> None:
    with pytest.raises(ValidationError):
        AuthorityProfileRecord(
            profile_name="unicode-collision",
            objects=(
                object_spec(path="Research/Café.md", object_id="opaque-object-001"),
                object_spec(path="Research/Cafe\u0301.md", object_id="opaque-object-002"),
            ),
        )


def test_exact_membership_must_reference_declared_objects_at_declared_parent() -> None:
    with pytest.raises(ValidationError):
        AuthorityProfileRecord(
            profile_name="unknown-child",
            objects=(object_spec(),),
            memberships=(
                ExactMembershipSpecRecord(
                    parent_id="opaque-parent-001", expected_child_ids=("unknown-object",)
                ),
            ),
        )

    with pytest.raises(ValidationError):
        AuthorityProfileRecord(
            profile_name="wrong-parent",
            objects=(object_spec(),),
            memberships=(
                ExactMembershipSpecRecord(
                    parent_id="other-parent", expected_child_ids=("opaque-object-001",)
                ),
            ),
        )


def test_hash_identity_is_separated_by_explicit_record_domain_and_domain_version() -> None:
    from typing import ClassVar, Literal

    from pydantic import BaseModel, ConfigDict

    class DomainA(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
        canonical_identity_domain: ClassVar[str] = "test.domain.a"
        canonical_identity_version: ClassVar[int] = 1
        schema_version: Literal[1] = 1
        value: str

    class DomainB(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
        canonical_identity_domain: ClassVar[str] = "test.domain.b"
        canonical_identity_version: ClassVar[int] = 1
        schema_version: Literal[1] = 1
        value: str

    class DomainA2(BaseModel):
        model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
        canonical_identity_domain: ClassVar[str] = "test.domain.a"
        canonical_identity_version: ClassVar[int] = 2
        schema_version: Literal[1] = 1
        value: str

    first = DomainA(value="same-payload")
    other_domain = DomainB(value="same-payload")
    other_domain_version = DomainA2(value="same-payload")

    assert canonical_record_bytes(first) == canonical_record_bytes(other_domain)
    assert canonical_record_bytes(first) == canonical_record_bytes(other_domain_version)
    assert canonical_record_hash(first) != canonical_record_hash(other_domain)
    assert canonical_record_hash(first) != canonical_record_hash(other_domain_version)


def test_runtime_dataclass_is_not_silently_treated_as_durable_canonical_record() -> None:
    runtime_profile = profile_from_record(profile())
    with pytest.raises(TypeError, match="Pydantic"):
        canonical_record_bytes(runtime_profile)  # type: ignore[arg-type]


def test_source_state_identity_changes_when_logical_mapping_changes_with_same_source_and_content() -> None:
    original = profile()
    original_readme = original.objects[1]
    remapped_readme = AuthorityObjectSpecRecord(
        logical_path="METHOD_AUTHORITY.md",
        provider=original_readme.provider,
        object_id=original_readme.object_id,
        expected_name=original_readme.expected_name,
        expected_mime_type=original_readme.expected_mime_type,
        expected_parent_id=original_readme.expected_parent_id,
        representation_schema=original_readme.representation_schema,
    )
    remapped = AuthorityProfileRecord(
        profile_name=original.profile_name,
        objects=(original.objects[0], remapped_readme),
    )

    original_state = SnapshotStateRecord(
        authority_spec_sha256=profile_from_record(original).spec_sha256,
        entries=(
            SemanticEntryRecord(
                logical_path="DECISIONS.md",
                representation_schema="test-representation-v1",
                content_sha256=H3,
            ),
            SemanticEntryRecord(
                logical_path="README.md",
                representation_schema="test-representation-v1",
                content_sha256=H2,
            ),
        ),
    )
    remapped_state = SnapshotStateRecord(
        authority_spec_sha256=profile_from_record(remapped).spec_sha256,
        entries=(
            SemanticEntryRecord(
                logical_path="DECISIONS.md",
                representation_schema="test-representation-v1",
                content_sha256=H3,
            ),
            SemanticEntryRecord(
                logical_path="METHOD_AUTHORITY.md",
                representation_schema="test-representation-v1",
                content_sha256=H2,
            ),
        ),
    )

    assert original_readme.object_id == remapped_readme.object_id
    assert {entry.content_sha256 for entry in original_state.entries} == {
        entry.content_sha256 for entry in remapped_state.entries
    }
    assert canonical_record_hash(original_state) != canonical_record_hash(remapped_state)


def test_safe_provenance_changes_observation_identity_not_source_state_identity() -> None:
    source_state_id = canonical_record_hash(state())
    first = observation(snapshot_hash=source_state_id)
    changed_provenance = first.provenance.model_copy(
        update={"auth_provenance": "adc:wif-service-account"}
    )
    second = first.model_copy(update={"provenance": changed_provenance})

    assert first.snapshot_state_sha256 == second.snapshot_state_sha256 == source_state_id
    assert canonical_record_hash(first) != canonical_record_hash(second)


def test_canonical_identity_protocol_version_is_bound_into_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    import canonical_sync.codec as codec

    value = state()
    original = codec.canonical_record_hash(value)
    monkeypatch.setattr(codec, "CANONICAL_IDENTITY_PROTOCOL_VERSION", 2)
    changed = codec.canonical_record_hash(value)

    assert original != changed
    assert not codec.canonical_record_bytes(value).endswith(b"\n")



def test_snapshot_state_canonical_identity_golden_vector() -> None:
    from canonical_sync.codec import canonical_identity_bytes

    value = SnapshotStateRecord(
        authority_spec_sha256="0" * 64,
        entries=(
            SemanticEntryRecord(
                logical_path="README.md",
                representation_schema="google-drive-export-markdown-v1",
                content_sha256="1" * 64,
            ),
        ),
    )
    expected_payload = (
        b'{"authority_spec_sha256":'
        b'"0000000000000000000000000000000000000000000000000000000000000000",'
        b'"entries":[{"content_sha256":'
        b'"1111111111111111111111111111111111111111111111111111111111111111",'
        b'"logical_path":"README.md",'
        b'"representation_schema":"google-drive-export-markdown-v1"}],'
        b'"record_type":"snapshot_state","schema_version":2}'
    )
    expected_identity = (
        b"canonical-sync-record-identity\x00"
        b"\x00\x00\x00\x01"
        b"\x00\x00\x00\x00\x00\x00\x00\x1b"
        b"canonical-sync.source-state"
        b"\x00\x00\x00\x01"
        b"\x00\x00\x00\x02"
        b"\x00\x00\x00\x00\x00\x00\x01\x45"
        + expected_payload
    )
    expected_hash = "9e056e7675cfee4a1881ce33e4485522dee57bdf3ef8bba72f1299c7048b6552"

    assert canonical_record_bytes(value) == expected_payload
    assert canonical_identity_bytes(value) == expected_identity
    assert canonical_record_hash(value) == expected_hash


def test_authority_profile_spec_sha256_updates_on_replace() -> None:
    from dataclasses import replace
    base_profile = profile_from_record(profile())
    initial_hash = base_profile.spec_sha256
    assert isinstance(initial_hash, str) and len(initial_hash) == 64

    first = base_profile.objects[0]
    modified_first = replace(first, expected_name=f"{first.expected_name}.modified")
    updated_profile = replace(base_profile, objects=(modified_first, *base_profile.objects[1:]))

    assert updated_profile.spec_sha256 != initial_hash
    assert len(updated_profile.spec_sha256) == 64
    restored_profile = replace(updated_profile, objects=base_profile.objects)
    assert restored_profile.spec_sha256 == initial_hash


def test_authority_profile_rejects_path_hierarchy_collisions() -> None:
    mime = "application/vnd.google-apps.document"
    spec1 = AuthorityObjectSpecRecord(
        logical_path="folder",
        provider="google_drive",
        object_id="obj-001",
        expected_name="folder",
        expected_mime_type=mime,
        representation_schema="schema-v1",
    )
    spec2 = AuthorityObjectSpecRecord(
        logical_path="folder/file.md",
        provider="google_drive",
        object_id="obj-002",
        expected_name="file.md",
        expected_mime_type=mime,
        representation_schema="schema-v1",
    )
    with pytest.raises(ValidationError, match="path hierarchy collision"):
        AuthorityProfileRecord(profile_name="collision", objects=(spec1, spec2))


def test_records_reject_lexical_interloper_hierarchy_and_directory_prefix_aliases() -> None:
    with pytest.raises(ValidationError, match="path hierarchy collision"):
        AuthorityProfileRecord(
            profile_name="interloper-collision",
            objects=(
                object_spec(path="a", object_id="obj-1"),
                object_spec(path="a-b", object_id="obj-2"),
                object_spec(path="a/c", object_id="obj-3"),
            ),
        )

    with pytest.raises(ValidationError, match="directory prefix"):
        AuthorityProfileRecord(
            profile_name="dir-prefix-case-collision",
            objects=(
                object_spec(path="Foo/a.txt", object_id="obj-1"),
                object_spec(path="foo/b.txt", object_id="obj-2"),
            ),
        )

    with pytest.raises(ValidationError, match="directory prefix"):
        SnapshotStateRecord(
            authority_spec_sha256=H1,
            entries=(
                SemanticEntryRecord(
                    logical_path="Café/a.txt",
                    representation_schema="v1",
                    content_sha256=H2,
                ),
                SemanticEntryRecord(
                    logical_path="Cafe\u0301/b.txt",
                    representation_schema="v1",
                    content_sha256=H3,
                ),
            ),
        )

    base_obs = observation(snapshot_hash=H1).sources[0]
    with pytest.raises(ValidationError, match="directory prefix"):
        SnapshotObservationRecord(
            snapshot_state_sha256=H1,
            authority_spec_sha256=H1,
            acquired_at=T0,
            attempt_count=1,
            provenance=observation(snapshot_hash=H1).provenance,
            sources=(
                base_obs.model_copy(update={"logical_path": "Foo/a.txt", "object_id": "obj-1"}),
                base_obs.model_copy(update={"logical_path": "foo/b.txt", "object_id": "obj-2"}),
            ),
        )


@pytest.mark.parametrize("bad_version", [True, 1.0, "1"])
def test_strict_schema_version_rejects_bool_float_and_str_on_direct_construction(
    bad_version: object,
) -> None:
    with pytest.raises(ValidationError):
        AuthorityProfileRecord(
            schema_version=bad_version,  # type: ignore[arg-type]
            profile_name="strict-schema-version",
            objects=(object_spec(),),
        )

