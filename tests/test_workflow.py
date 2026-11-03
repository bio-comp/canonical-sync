from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from canonical_sync.codec import canonical_record_bytes
from canonical_sync.domain import (
    SourceContent,
    SourceObservation,
    TransportProvenance,
    profile_from_record,
)
from canonical_sync.errors import AuthorityMismatchError, TransportAuthError
from canonical_sync.records import (
    AcquisitionProvenanceRecord,
    AcquisitionReceiptRecord,
    AuthorityObjectSpecRecord,
    AuthorityProfileRecord,
)
from canonical_sync.store import SnapshotStore
from canonical_sync.workflow import acquire_and_publish
from fakes import FakeTransport

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
MIME = "application/vnd.google-apps.document"
TEST_PROVENANCE = AcquisitionProvenanceRecord(
    runner_name="canonical-sync",
    runner_version="test",
    python_implementation="CPython",
    python_version="3.11.13",
    transport_name="fake-transport",
    transport_version="test-v1",
    auth_provenance="test-injected",
)


def _profile():
    return profile_from_record(
        AuthorityProfileRecord(
            profile_name="workflow-test",
            objects=(
                AuthorityObjectSpecRecord(
                    logical_path="README.md",
                    provider="google_drive",
                    object_id="object-001",
                    expected_name="README.md",
                    expected_mime_type=MIME,
                    expected_parent_id="parent-001",
                    representation_schema="test-representation-v1",
                ),
            ),
        )
    )


def _observation(*, name: str = "README.md") -> SourceObservation:
    return SourceObservation(
        object_id="object-001",
        name=name,
        mime_type=MIME,
        version=1,
        modified_time=T0,
        parent_ids=("parent-001",),
        trashed=False,
        can_download=True,
    )


def _transport(*, first_name: str = "README.md") -> FakeTransport:
    first = _observation(name=first_name)
    stable = _observation()
    return FakeTransport(
        observations={"object-001": [first, stable]},
        contents={
            "object-001": SourceContent(
                representation_schema="test-representation-v1",
                data=b"README\n",
            )
        },
    )


def _clock(*values: datetime):
    iterator = iter(values)
    return lambda: next(iterator)


def test_successful_workflow_persists_and_verifies_acquisition_receipt(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    result = acquire_and_publish(
        _transport(),
        _profile(),
        store,
        clock=_clock(T0, T0 + timedelta(seconds=1), T0 + timedelta(seconds=2)),
    )

    assert result.receipt.status == "success"
    assert result.receipt.transaction_attempt_count == 1
    assert result.receipt.snapshot_state_sha256 == result.publication.state_sha256
    assert result.receipt.snapshot_observation_sha256 == result.publication.observation_sha256
    assert result.receipt.provenance == result.candidate.observation.provenance
    assert store.verify_receipt(result.receipt_sha256) == result.receipt
    assert store.list_receipt_hashes() == (result.receipt_sha256,)


def test_failed_workflow_persists_sanitized_failure_receipt_then_reraises(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    with pytest.raises(AuthorityMismatchError):
        acquire_and_publish(
            _transport(first_name="WRONG.md"),
            _profile(),
            store,
            clock=_clock(T0, T0 + timedelta(seconds=1)),
        )

    hashes = store.list_receipt_hashes()
    assert len(hashes) == 1
    receipt = store.verify_receipt(hashes[0])
    assert receipt.status == "failed"
    assert receipt.transaction_attempt_count == 1
    assert receipt.error_code == "AuthorityMismatchError"
    assert receipt.provenance.transport_name.startswith("opaque-sha256:")
    assert receipt.provenance.auth_provenance == "test-injected"
    assert receipt.snapshot_state_sha256 is None
    assert receipt.snapshot_observation_sha256 is None


def test_failed_workflow_records_accurate_attempt_count_when_failure_follows_movement(
    tmp_path: Path,
) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    # Attempt 1: pre has version 1, post has version 2 (movement)
    first_pre = _observation()
    first_post = replace(first_pre, version=2, modified_time=T0 + timedelta(seconds=1))
    # Attempt 2: pre has mismatched name (authority failure)
    second_pre = replace(first_pre, name="MISMATCH.md")

    transport = FakeTransport(
        observations={"object-001": [first_pre, first_post, second_pre]},
        contents={
            "object-001": SourceContent(
                representation_schema="test-representation-v1",
                data=b"README\n",
            )
        },
    )

    with pytest.raises(AuthorityMismatchError):
        acquire_and_publish(
            transport,
            _profile(),
            store,
            max_movement_attempts=3,
            clock=_clock(T0, T0 + timedelta(seconds=1)),
        )

    hashes = store.list_receipt_hashes()
    assert len(hashes) == 1
    receipt = store.verify_receipt(hashes[0])
    assert receipt.status == "failed"
    assert receipt.transaction_attempt_count == 2
    assert receipt.error_code == "AuthorityMismatchError"


def test_acquisition_receipt_status_invariants_are_strict() -> None:
    with pytest.raises(ValidationError):
        AcquisitionReceiptRecord(
            started_at=T0,
            ended_at=T0,
            authority_spec_sha256="1" * 64,
            provenance=TEST_PROVENANCE,
            transaction_attempt_count=1,
            status="success",
            error_code=None,
            snapshot_state_sha256=None,
            snapshot_observation_sha256=None,
        )

    with pytest.raises(ValidationError):
        AcquisitionReceiptRecord(
            started_at=T0,
            ended_at=T0 - timedelta(seconds=1),
            authority_spec_sha256="1" * 64,
            provenance=TEST_PROVENANCE,
            transaction_attempt_count=0,
            status="failed",
            error_code="AuthorityMismatchError",
            snapshot_state_sha256=None,
            snapshot_observation_sha256=None,
        )


def test_failed_receipt_identity_includes_safe_provenance_but_not_raw_error_body(
    tmp_path: Path,
) -> None:
    raw_error = "SECRET-SENTINEL raw provider body /sensitive/credential/path"
    provenances = (
        TransportProvenance(
            transport_name="google-drive-v3",
            transport_version="client-a",
            auth_provenance="adc:authorized-user",
        ),
        TransportProvenance(
            transport_name="google-drive-v3",
            transport_version="client-b",
            auth_provenance="adc:workload-identity-service-account",
        ),
    )
    receipt_hashes: list[str] = []
    receipt_payloads: list[bytes] = []

    for index, provenance in enumerate(provenances):
        store = SnapshotStore(tmp_path / f"private-store-{index}")
        transport = _transport()
        transport._provenance = provenance
        transport._failures[("observe", "object-001")] = TransportAuthError(raw_error)
        with pytest.raises(TransportAuthError):
            acquire_and_publish(
                transport,
                _profile(),
                store,
                clock=_clock(T0, T0 + timedelta(seconds=1)),
            )
        hashes = store.list_receipt_hashes()
        assert len(hashes) == 1
        receipt = store.verify_receipt(hashes[0])
        assert receipt.status == "failed"
        assert receipt.error_code == "TransportAuthError"
        assert receipt.provenance.transport_version.startswith("opaque-sha256:")
        assert receipt.provenance.auth_provenance == provenance.auth_provenance
        receipt_hashes.append(hashes[0])
        receipt_payloads.append(canonical_record_bytes(receipt))

    assert receipt_hashes[0] != receipt_hashes[1]
    assert all(b"SECRET-SENTINEL" not in payload for payload in receipt_payloads)
    assert all(b"/sensitive/credential/path" not in payload for payload in receipt_payloads)


def test_programming_errors_propagate_without_manufacturing_failure_receipt(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    transport = _transport()
    transport._failures[("observe", "object-001")] = AssertionError("programming defect")

    with pytest.raises(AssertionError, match="programming defect"):
        acquire_and_publish(
            transport,
            _profile(),
            store,
            clock=_clock(T0, T0 + timedelta(seconds=1)),
        )

    assert store.list_receipt_hashes() == ()


def test_staging_io_failure_gets_sanitized_receipt(tmp_path, monkeypatch):
    import canonical_sync.store as module
    from canonical_sync.errors import SnapshotIntegrityError
    store = SnapshotStore(tmp_path / 'store')
    def fail(*args, **kwargs):
        raise PermissionError('FAKE_PATH_SECRET /private/credential')
    monkeypatch.setattr(module.tempfile, 'mkdtemp', fail)
    with pytest.raises(SnapshotIntegrityError):
        acquire_and_publish(_transport(), _profile(), store)
    receipt = store.verify_receipt(store.list_receipt_hashes()[0])
    assert b'FAKE_PATH_SECRET' not in canonical_record_bytes(receipt)


def test_untrusted_transport_metadata_never_enters_receipt(tmp_path):
    transport = _transport()
    transport._provenance = TransportProvenance(
        transport_name='FAKE_PROVIDER_SECRET',
        transport_version='/private/FAKE_VERSION_SECRET',
        auth_provenance='token=FAKE_AUTH_SECRET')
    result = acquire_and_publish(transport, _profile(), SnapshotStore(tmp_path / 'store'))
    payload = canonical_record_bytes(result.receipt)
    assert all(x not in payload for x in
               (b'FAKE_PROVIDER_SECRET', b'FAKE_VERSION_SECRET', b'FAKE_AUTH_SECRET'))


def test_historical_receipts_are_rejected_without_reinterpretation(tmp_path):
    from canonical_sync.codec import parse_canonical_record
    result = acquire_and_publish(_transport(), _profile(), SnapshotStore(tmp_path / 'store'))
    for old in (1, 2, 3):
        raw = result.receipt.model_copy(update={'schema_version': old})
        with pytest.raises(ValidationError):
            parse_canonical_record(canonical_record_bytes(raw), AcquisitionReceiptRecord)
    assert result.receipt.schema_version == 4
