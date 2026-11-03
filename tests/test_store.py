from __future__ import annotations

import os
import shutil
import stat
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from canonical_sync.acquisition import acquire_stable_candidate
from canonical_sync.codec import canonical_record_hash
from canonical_sync.domain import SourceContent, SourceObservation, profile_from_record
from canonical_sync.errors import SnapshotIntegrityError
from canonical_sync.records import AuthorityObjectSpecRecord, AuthorityProfileRecord
from canonical_sync.store import SnapshotStore
from fakes import FakeTransport

T0 = datetime(2026, 10, 26, 12, 0, tzinfo=UTC)
MIME = "application/vnd.google-apps.document"


def _candidate():
    specs = (
        AuthorityObjectSpecRecord(
            logical_path="README.md", provider="google_drive", object_id="object-001",
            expected_name="README.md", expected_mime_type=MIME, expected_parent_id="parent-001",
            representation_schema="test-representation-v1",
        ),
        AuthorityObjectSpecRecord(
            logical_path="Research/DECISIONS.md", provider="google_drive", object_id="object-002",
            expected_name="DECISIONS.md", expected_mime_type=MIME, expected_parent_id="parent-001",
            representation_schema="test-representation-v1",
        ),
    )
    profile = profile_from_record(AuthorityProfileRecord(profile_name="store-test", objects=specs))
    def obs(object_id: str, name: str) -> SourceObservation:
        return SourceObservation(
            object_id=object_id, name=name, mime_type=MIME, version=1, modified_time=T0,
            parent_ids=("parent-001",), trashed=False, can_download=True,
        )
    transport = FakeTransport(
        observations={
            "object-001": [obs("object-001", "README.md"), obs("object-001", "README.md")],
            "object-002": [obs("object-002", "DECISIONS.md"), obs("object-002", "DECISIONS.md")],
        },
        contents={
            "object-001": SourceContent("test-representation-v1", b"README\n"),
            "object-002": SourceContent("test-representation-v1", b"DECISIONS\n"),
        },
    )
    return acquire_stable_candidate(transport, profile, clock=lambda: T0)


def test_publish_verify_round_trip_and_existing_target_is_verified_noop(tmp_path: Path) -> None:
    candidate = _candidate()
    store = SnapshotStore(tmp_path / "private-store")
    first = store.publish(store.stage(candidate))
    second = store.publish(store.stage(candidate))
    verified = store.verify_completed(first.observation_sha256)

    assert first.published_state is True and first.published_observation is True
    assert second.published_state is False and second.published_observation is False
    assert verified.state == candidate.state
    assert verified.observation == candidate.observation
    assert {item.logical_path: item.data for item in verified.representations} == {
        "README.md": b"README\n",
        "Research/DECISIONS.md": b"DECISIONS\n",
    }


def test_symlinked_store_root_fails_closed(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        SnapshotStore(link)


def test_symlinked_operational_directory_fails_before_publication(tmp_path: Path) -> None:
    store_root = tmp_path / "private-store"
    store = SnapshotStore(store_root)
    snapshots = store_root / "snapshots"
    snapshots.rmdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    snapshots.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        store.publish(store.stage(_candidate()))
    assert list(outside.iterdir()) == []


def test_tampered_staged_content_fails_before_publication(tmp_path: Path) -> None:
    candidate = _candidate()
    store = SnapshotStore(tmp_path / "private-store")
    staged = store.stage(candidate)
    (staged.path / "snapshot" / "files" / "README.md").write_bytes(b"tampered")
    with pytest.raises(SnapshotIntegrityError, match="hash"):
        store.publish(staged)
    state_hash = canonical_record_hash(candidate.state)
    assert not (store.root / "snapshots" / state_hash).exists()


def test_corrupt_existing_target_is_never_overwritten(tmp_path: Path) -> None:
    candidate = _candidate()
    store = SnapshotStore(tmp_path / "private-store")
    staged = store.stage(candidate)
    target = store.root / "snapshots" / canonical_record_hash(candidate.state)
    target.mkdir()
    (target / "state.json").write_bytes(b"corrupt")
    before = (target / "state.json").read_bytes()
    with pytest.raises(SnapshotIntegrityError):
        store.publish(staged)
    assert (target / "state.json").read_bytes() == before


def test_orphan_semantic_snapshot_is_not_a_completed_acquisition(tmp_path: Path) -> None:
    candidate = _candidate()
    store = SnapshotStore(tmp_path / "private-store")
    result = store.publish(store.stage(candidate))
    observation_dir = store.root / "observations" / result.observation_sha256
    for child in observation_dir.iterdir():
        child.unlink()
    observation_dir.rmdir()
    assert (store.root / "snapshots" / result.state_sha256).is_dir()
    with pytest.raises(SnapshotIntegrityError, match="observation"):
        store.verify_completed(result.observation_sha256)


def test_unexpected_or_symlinked_snapshot_inventory_fails_verification(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    result = store.publish(store.stage(_candidate()))
    snapshot = store.root / "snapshots" / result.state_sha256
    (snapshot / "unexpected.txt").write_text("x")
    with pytest.raises(SnapshotIntegrityError, match="inventory"):
        store.verify_completed(result.observation_sha256)
    (snapshot / "unexpected.txt").unlink()
    target = snapshot / "files" / "README.md"
    target.unlink()
    target.symlink_to(snapshot / "state.json")
    with pytest.raises(SnapshotIntegrityError, match="regular"):
        store.verify_completed(result.observation_sha256)


def test_identical_concurrent_publishers_serialize_to_publish_and_noop(tmp_path: Path) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    candidate = _candidate()
    staged = (store.stage(candidate), store.stage(candidate))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(store.publish, staged))
    assert sum(result.published_state for result in results) == 1
    assert sum(result.published_observation for result in results) == 1
    store.verify_completed(results[0].observation_sha256)


def test_symlinked_receipts_directory_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "private-store"
    store = SnapshotStore(root)
    receipts = root / "receipts"
    receipts.rmdir()
    outside = tmp_path / "outside-receipts"
    outside.mkdir()
    receipts.symlink_to(outside, target_is_directory=True)
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        store.list_receipt_hashes()
    assert list(outside.iterdir()) == []


def test_partial_staging_artifact_never_counts_as_completed_state(tmp_path: Path) -> None:
    root = tmp_path / "private-store"
    store = SnapshotStore(root)
    partial = root / "staging" / "interrupted"
    partial.mkdir()
    (partial / "partial.bin").write_bytes(b"partial")
    assert store.list_receipt_hashes() == ()
    assert list((root / "snapshots").iterdir()) == []
    assert list((root / "observations").iterdir()) == []


def test_operational_io_failure_during_construction_sanitizes_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sentinel_path = "/secret/private/credentials/store"

    def fail_mkdir(*args: object, **kwargs: object) -> None:
        raise OSError(13, "Permission denied", sentinel_path)

    monkeypatch.setattr(Path, "mkdir", fail_mkdir)

    with pytest.raises(SnapshotIntegrityError) as exc_info:
        SnapshotStore(tmp_path / "fail-store")

    err = exc_info.value
    assert sentinel_path not in str(err)
    assert err.__cause__ is None or sentinel_path not in str(err.__cause__)


def test_operational_io_failure_during_stage_sanitizes_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    candidate = _candidate()
    sentinel_path = "/secret/private/path/sentinel.txt"

    import canonical_sync.store as store_mod

    def fail_write(path: Path, data: bytes) -> None:
        raise OSError(5, "Input/output error", sentinel_path)

    monkeypatch.setattr(store_mod, "_write_fsync", fail_write)

    with pytest.raises(SnapshotIntegrityError) as exc_info:
        store.stage(candidate)

    err = exc_info.value
    assert sentinel_path not in str(err)
    assert err.__cause__ is None or sentinel_path not in str(err.__cause__)


def test_operational_io_failure_during_publish_sanitizes_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    candidate = _candidate()
    staged = store.stage(candidate)
    sentinel_path = "/secret/private/path/rename.target"

    def fail_rename(src: object, dst: object) -> None:
        raise OSError(18, "Cross-device link", sentinel_path)

    monkeypatch.setattr(os, "rename", fail_rename)

    with pytest.raises(SnapshotIntegrityError) as exc_info:
        store.publish(staged)

    err = exc_info.value
    assert sentinel_path not in str(err)
    assert err.__cause__ is None or sentinel_path not in str(err.__cause__)


def test_operational_io_failure_during_verify_completed_sanitizes_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = SnapshotStore(tmp_path / "private-store")
    candidate = _candidate()
    result = store.publish(store.stage(candidate))
    sentinel_path = "/secret/private/path/read.bin"

    def fail_read_bytes(self: Path) -> bytes:
        raise OSError(13, "Permission denied", sentinel_path)

    monkeypatch.setattr(Path, "read_bytes", fail_read_bytes)

    with pytest.raises(SnapshotIntegrityError) as exc_info:
        store.verify_completed(result.observation_sha256)

    err = exc_info.value
    assert sentinel_path not in str(err)
    assert err.__cause__ is None or sentinel_path not in str(err.__cause__)


def test_symlink_rejection_and_macos_platform_alias_regression(tmp_path: Path) -> None:
    # 1. Existing symlink used as store root remains rejected
    real_dir = tmp_path / "real_dir"
    real_dir.mkdir()
    sym_root = tmp_path / "sym_root"
    sym_root.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        SnapshotStore(sym_root)

    # 2. Symlinked operational directory remains rejected
    valid_store_root = tmp_path / "valid_store"
    store = SnapshotStore(valid_store_root)
    snapshots_dir = valid_store_root / "snapshots"
    snapshots_dir.rmdir()
    outside_dir = tmp_path / "outside_snapshots"
    outside_dir.mkdir()
    snapshots_dir.symlink_to(outside_dir, target_is_directory=True)
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        store._validate_operational_dirs()

    # 3. Relative paths and '..' cannot bypass symlink detection
    sym_child = tmp_path / "sym_parent"
    sym_child.symlink_to(real_dir, target_is_directory=True)
    bypass_attempt = sym_child / "sub"
    with pytest.raises(SnapshotIntegrityError, match="symlink"):
        SnapshotStore(bypass_attempt)

    # 4. Legitimate macOS root platform alias (/tmp /var) does not fail merely due to OS alias
    # Test with /tmp/test-snapshot-store-path if on macOS and /tmp is a symlink
    if stat.S_ISLNK(os.lstat("/tmp").st_mode):
        mac_tmp_store = Path("/tmp") / f"test-store-{os.getpid()}"
        try:
            s = SnapshotStore(mac_tmp_store)
            assert s.root == mac_tmp_store
            # Root itself cannot be a symlink
            with pytest.raises(SnapshotIntegrityError, match="symlink"):
                SnapshotStore(Path("/tmp"))
        finally:
            shutil.rmtree(mac_tmp_store, ignore_errors=True)


def test_nested_snapshot_syncs_complete_directory_hierarchy_deepest_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import canonical_sync.store as store_mod

    specs = (
        AuthorityObjectSpecRecord(
            logical_path="nested/deeper/README.md",
            provider="google_drive",
            object_id="object-nested",
            expected_name="README.md",
            expected_mime_type=MIME,
            expected_parent_id="parent-001",
            representation_schema="test-representation-v1",
        ),
    )
    profile = profile_from_record(AuthorityProfileRecord(profile_name="nested-test", objects=specs))

    def obs(object_id: str, name: str) -> SourceObservation:
        return SourceObservation(
            object_id=object_id,
            name=name,
            mime_type=MIME,
            version=1,
            modified_time=T0,
            parent_ids=("parent-001",),
            trashed=False,
            can_download=True,
        )

    transport = FakeTransport(
        observations={
            "object-nested": [obs("object-nested", "README.md"), obs("object-nested", "README.md")],
        },
        contents={
            "object-nested": SourceContent("test-representation-v1", b"NESTED CONTENT\n"),
        },
    )
    candidate = acquire_stable_candidate(transport, profile, clock=lambda: T0)

    synced_directories: list[Path] = []
    real_fsync_dir = store_mod._fsync_dir

    def recording_fsync_dir(path: Path) -> None:
        synced_directories.append(path)
        real_fsync_dir(path)

    monkeypatch.setattr(store_mod, "_fsync_dir", recording_fsync_dir)

    store = SnapshotStore(tmp_path / "nested-store")
    # Reset tracking before staging
    synced_directories.clear()

    staged = store.stage(candidate)
    staged_root = staged.path
    files_dir = staged_root / "snapshot" / "files"
    nested_dir = files_dir / "nested"
    deeper_dir = nested_dir / "deeper"

    assert files_dir in synced_directories
    assert nested_dir in synced_directories
    assert deeper_dir in synced_directories
    assert (staged_root / "snapshot") in synced_directories
    assert (staged_root / "observation") in synced_directories
    assert staged_root in synced_directories

    # Verify deepest-first order: every child directory must appear before its parent
    deeper_idx = synced_directories.index(deeper_dir)
    nested_idx = synced_directories.index(nested_dir)
    files_idx = synced_directories.index(files_dir)
    snapshot_idx = synced_directories.index(staged_root / "snapshot")
    stage_idx = synced_directories.index(staged_root)

    assert deeper_idx < nested_idx < files_idx < snapshot_idx < stage_idx

    # Successful publication and completed verification succeeds
    result = store.publish(staged)
    assert result.published_state is True
    assert result.published_observation is True
    verified = store.verify_completed(result.observation_sha256)
    assert verified.state == candidate.state
    assert verified.observation == candidate.observation
