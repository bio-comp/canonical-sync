from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from canonical_sync.acquisition import acquire_stable_candidate
from canonical_sync.codec import canonical_record_hash
from canonical_sync.domain import SourceContent, SourceObservation, profile_from_record
from canonical_sync.errors import (
    AuthorityMismatchError,
    SourceMovementError,
    TransportAuthError,
    TransportPermanentError,
)
from canonical_sync.records import (
    AuthorityObjectSpecRecord,
    AuthorityProfileRecord,
    ExactMembershipSpecRecord,
)
from fakes import FakeTransport

MIME = "application/vnd.google-apps.document"
T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)


def spec(path: str, object_id: str) -> AuthorityObjectSpecRecord:
    return AuthorityObjectSpecRecord(
        logical_path=path,
        provider="google_drive",
        object_id=object_id,
        expected_name=path,
        expected_mime_type=MIME,
        expected_parent_id="parent-001",
        representation_schema="test-representation-v1",
    )


def profile(*, with_membership: bool = False):
    memberships = (
        ExactMembershipSpecRecord(
            parent_id="parent-001",
            expected_child_ids=("object-001", "object-002"),
        ),
    ) if with_membership else ()
    return profile_from_record(
        AuthorityProfileRecord(
            profile_name="llm-evaluation-test",
            objects=(spec("README.md", "object-001"), spec("DECISIONS.md", "object-002")),
            memberships=memberships,
        )
    )


def observed(
    object_id: str,
    name: str,
    *,
    version: int = 1,
    modified_time: datetime = T0,
    parent_id: str = "parent-001",
    mime_type: str = MIME,
    trashed: bool = False,
) -> SourceObservation:
    return SourceObservation(
        object_id=object_id,
        name=name,
        mime_type=mime_type,
        version=version,
        modified_time=modified_time,
        parent_ids=(parent_id,),
        trashed=trashed,
        can_download=True,
    )


def content(data: bytes) -> SourceContent:
    return SourceContent(representation_schema="test-representation-v1", data=data)


def stable_transport(*, version: int = 1, first_data: bytes = b"README\n") -> FakeTransport:
    return FakeTransport(
        observations={
            "object-001": [
                observed("object-001", "README.md", version=version),
                observed("object-001", "README.md", version=version),
            ],
            "object-002": [
                observed("object-002", "DECISIONS.md", version=version),
                observed("object-002", "DECISIONS.md", version=version),
            ],
        },
        contents={
            "object-001": content(first_data),
            "object-002": content(b"DECISIONS\n"),
        },
    )


def test_stable_multi_object_acquisition_builds_deterministic_semantic_state() -> None:
    result = acquire_stable_candidate(stable_transport(), profile(), clock=lambda: T0)

    assert result.attempt_count == 1
    assert [item.logical_path for item in result.representations] == ["DECISIONS.md", "README.md"]
    hashes = {item.logical_path: item.content_sha256 for item in result.representations}
    assert hashes["README.md"] == hashlib.sha256(b"README\n").hexdigest()
    assert result.observation.snapshot_state_sha256 == canonical_record_hash(result.state)
    assert {entry.logical_path for entry in result.state.entries} == {"README.md", "DECISIONS.md"}


def test_observation_identity_records_transport_runtime_and_auth_provenance() -> None:
    result = acquire_stable_candidate(stable_transport(), profile(), clock=lambda: T0)

    provenance = result.observation.provenance
    assert provenance.runner_name == "canonical-sync"
    assert provenance.runner_version
    assert provenance.python_implementation
    assert provenance.python_version
    assert provenance.transport_name.startswith("opaque-sha256:")
    assert provenance.transport_version.startswith("opaque-sha256:")
    assert provenance.auth_provenance == "test-injected"


def test_metadata_only_churn_changes_observation_not_semantic_state() -> None:
    first = acquire_stable_candidate(stable_transport(version=1), profile(), clock=lambda: T0)
    second = acquire_stable_candidate(
        stable_transport(version=9),
        profile(),
        clock=lambda: T0 + timedelta(minutes=1),
    )

    assert canonical_record_hash(first.state) == canonical_record_hash(second.state)
    assert canonical_record_hash(first.observation) != canonical_record_hash(second.observation)


def test_one_byte_source_change_changes_semantic_identity() -> None:
    first = acquire_stable_candidate(stable_transport(first_data=b"README\n"), profile(), clock=lambda: T0)
    second = acquire_stable_candidate(stable_transport(first_data=b"README!\n"), profile(), clock=lambda: T0)
    assert canonical_record_hash(first.state) != canonical_record_hash(second.state)


@pytest.mark.parametrize(
    "bad",
    [
        observed("wrong-id", "README.md"),
        observed("object-001", "OTHER.md"),
        observed("object-001", "README.md", parent_id="wrong-parent"),
        observed("object-001", "README.md", mime_type="text/plain"),
        observed("object-001", "README.md", trashed=True),
    ],
)
def test_exact_registered_authority_mismatch_fails_closed(bad: SourceObservation) -> None:
    transport = stable_transport()
    transport._observations["object-001"][0] = bad
    with pytest.raises(AuthorityMismatchError):
        acquire_stable_candidate(transport, profile(), clock=lambda: T0)
    assert transport.calls[("read", "object-001")] == 0


def test_source_movement_retries_the_entire_profile() -> None:
    first_pre = observed("object-001", "README.md", version=1)
    first_post = replace(first_pre, version=2, modified_time=T0 + timedelta(seconds=1))
    stable = replace(first_pre, version=2, modified_time=T0 + timedelta(seconds=1))
    second_source = observed("object-002", "DECISIONS.md", version=1)
    transport = FakeTransport(
        observations={
            "object-001": [first_pre, first_post, stable, stable],
            "object-002": [second_source, second_source, second_source, second_source],
        },
        contents={
            "object-001": content(b"README\n"),
            "object-002": content(b"DECISIONS\n"),
        },
    )

    result = acquire_stable_candidate(transport, profile(), max_movement_attempts=2, clock=lambda: T0)
    assert result.attempt_count == 2
    assert transport.calls[("read", "object-001")] == 2
    assert transport.calls[("read", "object-002")] == 2


def test_repeated_movement_exhausts_without_returning_mixed_candidate() -> None:
    a1 = observed("object-001", "README.md", version=1)
    a2 = replace(a1, version=2, modified_time=T0 + timedelta(seconds=1))
    a3 = replace(a1, version=3, modified_time=T0 + timedelta(seconds=2))
    b = observed("object-002", "DECISIONS.md", version=1)
    transport = FakeTransport(
        observations={
            "object-001": [a1, a2, a2, a3],
            "object-002": [b, b, b, b],
        },
        contents={"object-001": content(b"README\n"), "object-002": content(b"DECISIONS\n")},
    )

    with pytest.raises(SourceMovementError, match="every bounded acquisition attempt"):
        acquire_stable_candidate(transport, profile(), max_movement_attempts=2, clock=lambda: T0)
    assert transport.calls[("read", "object-001")] == 2
    assert transport.calls[("read", "object-002")] == 2


def test_exact_membership_rejects_unexpected_member() -> None:
    base = stable_transport()
    unexpected = observed("object-003", "EXTRA.md")
    base._memberships["parent-001"] = [
        (
            observed("object-001", "README.md"),
            observed("object-002", "DECISIONS.md"),
            unexpected,
        )
    ]
    with pytest.raises(AuthorityMismatchError, match="membership"):
        acquire_stable_candidate(base, profile(with_membership=True), clock=lambda: T0)


def test_membership_movement_retries_whole_transaction() -> None:
    first = (
        observed("object-001", "README.md"),
        observed("object-002", "DECISIONS.md"),
    )
    moved = (
        replace(first[0], version=2, modified_time=T0 + timedelta(seconds=1)),
        first[1],
    )
    stable_transport_value = FakeTransport(
        observations={
            "object-001": [first[0], first[0], first[0], first[0]],
            "object-002": [first[1], first[1], first[1], first[1]],
        },
        contents={"object-001": content(b"README\n"), "object-002": content(b"DECISIONS\n")},
        memberships={"parent-001": [first, moved, moved, moved]},
    )
    result = acquire_stable_candidate(
        stable_transport_value,
        profile(with_membership=True),
        max_movement_attempts=2,
        clock=lambda: T0,
    )
    assert result.attempt_count == 2
    assert stable_transport_value.calls[("read", "object-001")] == 2


@pytest.mark.parametrize("failure", [TransportAuthError("auth"), TransportPermanentError("permanent")])
def test_nonmovement_transport_failures_are_not_retried(failure: BaseException) -> None:
    transport = stable_transport()
    transport._failures[("read", "object-001")] = failure
    with pytest.raises(type(failure)):
        acquire_stable_candidate(transport, profile(), max_movement_attempts=3, clock=lambda: T0)
    assert transport.calls[("read", "object-001")] == 1


@pytest.mark.parametrize(
    "bad_paths",
    [
        (".",),
        (".g\u200cit/config",),
        ("a", "a-b", "a/c"),
        ("Foo/a.txt", "foo/b.txt"),
    ],
)
def test_invalid_authority_configuration_rejected_before_provider_reads(
    bad_paths: tuple[str, ...],
) -> None:
    from canonical_sync.domain import AuthorityObjectSpec, AuthorityProfile

    transport = stable_transport()
    with pytest.raises(ValueError):
        bad_profile = AuthorityProfile(
            profile_name="invalid-config",
            objects=tuple(
                AuthorityObjectSpec(
                    logical_path=p,
                    provider="google_drive",
                    object_id=f"object-00{idx}",
                    expected_name=p,
                    expected_mime_type=MIME,
                    expected_parent_id="parent-001",
                    representation_schema="test-representation-v1",
                )
                for idx, p in enumerate(bad_paths, start=1)
            ),
        )
        acquire_stable_candidate(transport, bad_profile, clock=lambda: T0)
    assert dict(transport.calls) == {}
