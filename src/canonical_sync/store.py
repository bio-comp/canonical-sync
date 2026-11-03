from __future__ import annotations

import fcntl
import hashlib
import os
import shutil
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .acquisition import AcquiredRepresentation, AcquisitionCandidate
from .codec import canonical_record_bytes, canonical_record_hash, parse_canonical_record
from .errors import SnapshotIntegrityError
from .records import AcquisitionReceiptRecord, SnapshotObservationRecord, SnapshotStateRecord


DIR_STAGING = "staging"
DIR_SNAPSHOTS = "snapshots"
DIR_OBSERVATIONS = "observations"
DIR_RECEIPTS = "receipts"
FILE_STATE = "state.json"
FILE_MANIFEST = "manifest.json"
FILE_LOCK = ".lock"


@dataclass(frozen=True, slots=True)
class StagedAcquisition:
    path: Path
    state_sha256: str
    observation_sha256: str

    def __post_init__(self) -> None:
        for val, label in (
            (self.state_sha256, "state hash"),
            (self.observation_sha256, "observation hash"),
        ):
            if len(val) != 64 or any(c not in "0123456789abcdef" for c in val):
                raise SnapshotIntegrityError(f"staged {label} is malformed")


@dataclass(frozen=True, slots=True)
class PublicationResult:
    state_sha256: str
    observation_sha256: str
    published_state: bool
    published_observation: bool


@dataclass(frozen=True, slots=True)
class VerifiedSnapshot:
    state: SnapshotStateRecord
    observation: SnapshotObservationRecord
    representations: tuple[AcquiredRepresentation, ...]


def _is_platform_root_alias(path: Path) -> bool:
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if not stat.S_ISLNK(st.st_mode):
        return False
    if path.parent != Path("/"):
        return False
    if hasattr(st, "st_uid") and st.st_uid != 0:
        return False
    try:
        resolved = path.resolve()
        return resolved.is_dir() and os.lstat(resolved).st_uid == 0
    except OSError:
        return False


def _reject_symlink_chain(path: Path) -> None:
    current = path.absolute()
    try:
        mode = os.lstat(current).st_mode
        if stat.S_ISLNK(mode):
            raise SnapshotIntegrityError("snapshot store path contains a symlink")
    except FileNotFoundError:
        pass
    except OSError:
        raise SnapshotIntegrityError("snapshot-store path could not be accessed safely") from None

    while True:
        if current.parent == current:
            break
        current = current.parent
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            continue
        except OSError:
            raise SnapshotIntegrityError("snapshot-store path could not be accessed safely") from None
        if stat.S_ISLNK(mode):
            if _is_platform_root_alias(current):
                continue
            raise SnapshotIntegrityError("snapshot store path contains a symlink")


def _require_directory(path: Path) -> None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise SnapshotIntegrityError("required snapshot-store directory is missing") from None
    except OSError:
        raise SnapshotIntegrityError("snapshot-store operational directory could not be accessed") from None
    if stat.S_ISLNK(mode):
        raise SnapshotIntegrityError("snapshot-store directory is a symlink")
    if not stat.S_ISDIR(mode):
        raise SnapshotIntegrityError("snapshot-store operational path is not a directory")


def _require_regular(path: Path) -> None:
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        raise SnapshotIntegrityError("required snapshot file is missing") from None
    except OSError:
        raise SnapshotIntegrityError("snapshot file could not be accessed") from None
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        raise SnapshotIntegrityError("snapshot entries must be regular files; symlink rejected")


def _fsync_dir(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        raise SnapshotIntegrityError("snapshot-store directory could not be opened for fsync") from None
    try:
        os.fsync(fd)
    except OSError:
        raise SnapshotIntegrityError("snapshot-store directory fsync failed") from None
    finally:
        os.close(fd)


def _write_fsync(path: Path, data: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        raise SnapshotIntegrityError("snapshot-store entry write failed") from None


class SnapshotStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        _reject_symlink_chain(root)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise SnapshotIntegrityError("snapshot-store root directory could not be created") from None
        _require_directory(root)
        self._staging = root / DIR_STAGING
        self._snapshots = root / DIR_SNAPSHOTS
        self._observations = root / DIR_OBSERVATIONS
        self._receipts = root / DIR_RECEIPTS
        try:
            for directory in (self._staging, self._snapshots, self._observations, self._receipts):
                directory.mkdir(exist_ok=True)
                _require_directory(directory)
            _fsync_dir(root)
        except OSError:
            raise SnapshotIntegrityError("snapshot-store operational directory could not be initialized") from None

    def _validate_operational_dirs(self) -> None:
        _reject_symlink_chain(self.root)
        _require_directory(self.root)
        for directory in (self._staging, self._snapshots, self._observations, self._receipts):
            _require_directory(directory)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self._validate_operational_dirs()
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.root / FILE_LOCK, flags, 0o600)
        except OSError:
            raise SnapshotIntegrityError("snapshot lock could not be opened safely") from None
        try:
            try:
                mode = os.fstat(fd).st_mode
            except OSError:
                raise SnapshotIntegrityError("snapshot lock stat failed") from None
            if not stat.S_ISREG(mode):
                raise SnapshotIntegrityError("snapshot lock must be a regular file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
            except OSError:
                raise SnapshotIntegrityError("snapshot lock acquisition failed") from None
            yield
        finally:
            try:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            finally:
                os.close(fd)

    @staticmethod
    def _validate_candidate(candidate: AcquisitionCandidate) -> None:
        state_hash = canonical_record_hash(candidate.state)
        if state_hash != candidate.observation.snapshot_state_sha256:
            raise SnapshotIntegrityError("snapshot state hash does not match observation")
        if candidate.state.authority_spec_sha256 != candidate.observation.authority_spec_sha256:
            raise SnapshotIntegrityError("authority specification hash does not match observation")
        state_entries = {entry.logical_path: entry for entry in candidate.state.entries}
        observation_entries = {entry.logical_path: entry for entry in candidate.observation.sources}
        representations = {entry.logical_path: entry for entry in candidate.representations}
        if set(state_entries) != set(observation_entries) or set(state_entries) != set(representations):
            raise SnapshotIntegrityError("snapshot candidate inventories do not match")
        for logical_path, representation in representations.items():
            digest = hashlib.sha256(representation.data).hexdigest()
            if digest != representation.content_sha256:
                raise SnapshotIntegrityError("snapshot representation hash mismatch")
            state_entry = state_entries[logical_path]
            observation_entry = observation_entries[logical_path]
            if (
                digest != state_entry.content_sha256
                or digest != observation_entry.content_sha256
                or representation.representation_schema != state_entry.representation_schema
                or representation.representation_schema != observation_entry.representation_schema
            ):
                raise SnapshotIntegrityError("snapshot representation metadata mismatch")

    def stage(self, candidate: AcquisitionCandidate) -> StagedAcquisition:
        self._validate_operational_dirs()
        self._validate_candidate(candidate)
        try:
            stage_root = Path(tempfile.mkdtemp(prefix="acquisition-", dir=self._staging))
        except OSError:
            raise SnapshotIntegrityError("snapshot staging directory could not be created") from None
        try:
            snapshot_root = stage_root / "snapshot"
            observation_root = stage_root / "observation"
            try:
                (snapshot_root / "files").mkdir(parents=True)
                observation_root.mkdir()
            except OSError:
                raise SnapshotIntegrityError("snapshot staging directories could not be created") from None
            _write_fsync(snapshot_root / FILE_STATE, canonical_record_bytes(candidate.state))
            for representation in candidate.representations:
                _write_fsync(snapshot_root / "files" / representation.logical_path, representation.data)
            _write_fsync(
                observation_root / "observation.json",
                canonical_record_bytes(candidate.observation),
            )
            try:
                all_dirs = {path for path in stage_root.rglob("*") if path.is_dir()}
                all_dirs.add(stage_root)
                for directory in sorted(
                    all_dirs,
                    key=lambda item: len(item.parts),
                    reverse=True,
                ):
                    _fsync_dir(directory)
                _fsync_dir(self._staging)
            except OSError:
                raise SnapshotIntegrityError("snapshot staging directory sync failed") from None
            return StagedAcquisition(
                path=stage_root,
                state_sha256=canonical_record_hash(candidate.state),
                observation_sha256=canonical_record_hash(candidate.observation),
            )
        except SnapshotIntegrityError:
            shutil.rmtree(stage_root, ignore_errors=True)
            raise
        except OSError:
            shutil.rmtree(stage_root, ignore_errors=True)
            raise SnapshotIntegrityError("snapshot staging I/O failed") from None
        except Exception:
            shutil.rmtree(stage_root, ignore_errors=True)
            raise

    def _verify_snapshot_dir(
        self, path: Path, expected_hash: str
    ) -> tuple[SnapshotStateRecord, tuple[AcquiredRepresentation, ...]]:
        _require_directory(path)
        state_path = path / FILE_STATE
        _require_regular(state_path)
        try:
            data = state_path.read_bytes()
        except OSError:
            raise SnapshotIntegrityError("snapshot state file could not be read") from None
        try:
            state = parse_canonical_record(data, SnapshotStateRecord)
        except (OSError, ValueError):
            raise SnapshotIntegrityError("snapshot state record failed canonical validation") from None
        if canonical_record_hash(state) != expected_hash:
            raise SnapshotIntegrityError("snapshot state hash mismatch")
        expected_files = {Path(FILE_STATE)}
        expected_dirs = {Path("files")}
        representations: list[AcquiredRepresentation] = []
        for entry in state.entries:
            relative = Path("files") / entry.logical_path
            expected_files.add(relative)
            parent = relative.parent
            while parent != Path("."):
                expected_dirs.add(parent)
                if parent == Path("files"):
                    break
                parent = parent.parent
            file_path = path / relative
            _require_regular(file_path)
            try:
                data = file_path.read_bytes()
            except OSError:
                raise SnapshotIntegrityError("snapshot content file could not be read") from None
            digest = hashlib.sha256(data).hexdigest()
            if digest != entry.content_sha256:
                raise SnapshotIntegrityError("snapshot content hash mismatch")
            representations.append(
                AcquiredRepresentation(
                    logical_path=entry.logical_path,
                    representation_schema=entry.representation_schema,
                    data=data,
                    content_sha256=digest,
                )
            )
        actual_files: set[Path] = set()
        actual_dirs: set[Path] = set()
        try:
            items = list(path.rglob("*"))
        except OSError:
            raise SnapshotIntegrityError("snapshot inventory traversal failed") from None
        for item in items:
            try:
                relative = item.relative_to(path)
                mode = os.lstat(item).st_mode
            except OSError:
                raise SnapshotIntegrityError("snapshot entry could not be accessed safely") from None
            if stat.S_ISLNK(mode):
                raise SnapshotIntegrityError("snapshot entries must be regular files/directories; symlink rejected")
            if stat.S_ISREG(mode):
                actual_files.add(relative)
            elif stat.S_ISDIR(mode):
                actual_dirs.add(relative)
            else:
                raise SnapshotIntegrityError("snapshot inventory contains a non-regular entry")
        if actual_files != expected_files or actual_dirs != expected_dirs:
            raise SnapshotIntegrityError("snapshot inventory is not exact")
        return state, tuple(sorted(representations, key=lambda item: item.logical_path))

    def _verify_observation_dir(self, path: Path, expected_hash: str) -> SnapshotObservationRecord:
        _require_directory(path)
        try:
            items = list(path.iterdir())
        except OSError:
            raise SnapshotIntegrityError("observation inventory traversal failed") from None
        if len(items) != 1 or items[0].name != "observation.json":
            raise SnapshotIntegrityError("observation inventory is not exact")
        observation_path = path / "observation.json"
        _require_regular(observation_path)
        try:
            data = observation_path.read_bytes()
        except OSError:
            raise SnapshotIntegrityError("observation file could not be read") from None
        try:
            observation = parse_canonical_record(data, SnapshotObservationRecord)
        except (OSError, ValueError):
            raise SnapshotIntegrityError("observation record failed canonical validation") from None
        if canonical_record_hash(observation) != expected_hash:
            raise SnapshotIntegrityError("observation hash mismatch")
        return observation

    def publish(self, staged: StagedAcquisition) -> PublicationResult:
        self._validate_operational_dirs()
        if staged.path.parent != self._staging:
            raise SnapshotIntegrityError("staged acquisition is outside this store")
        _require_directory(staged.path)
        staged_snapshot = staged.path / "snapshot"
        staged_observation = staged.path / "observation"
        state, _ = self._verify_snapshot_dir(staged_snapshot, staged.state_sha256)
        observation = self._verify_observation_dir(staged_observation, staged.observation_sha256)
        if observation.snapshot_state_sha256 != staged.state_sha256:
            raise SnapshotIntegrityError("staged observation points at the wrong semantic state")
        if observation.authority_spec_sha256 != state.authority_spec_sha256:
            raise SnapshotIntegrityError("staged authority identity is inconsistent")

        published_state = False
        published_observation = False
        try:
            with self._locked():
                state_target = self._snapshots / staged.state_sha256
                if state_target.exists():
                    self._verify_snapshot_dir(state_target, staged.state_sha256)
                    shutil.rmtree(staged_snapshot)
                else:
                    os.rename(staged_snapshot, state_target)
                    _fsync_dir(self._snapshots)
                    published_state = True

                observation_target = self._observations / staged.observation_sha256
                if observation_target.exists():
                    self._verify_observation_dir(observation_target, staged.observation_sha256)
                    shutil.rmtree(staged_observation)
                else:
                    os.rename(staged_observation, observation_target)
                    _fsync_dir(self._observations)
                    published_observation = True
                staged.path.rmdir()
                _fsync_dir(self._staging)
        except SnapshotIntegrityError:
            raise
        except OSError:
            raise SnapshotIntegrityError("snapshot publication I/O failed") from None

        self.verify_completed(staged.observation_sha256)
        return PublicationResult(
            state_sha256=staged.state_sha256,
            observation_sha256=staged.observation_sha256,
            published_state=published_state,
            published_observation=published_observation,
        )

    def _verify_receipt_file(
        self, path: Path, expected_hash: str
    ) -> AcquisitionReceiptRecord:
        _require_regular(path)
        try:
            data = path.read_bytes()
        except OSError:
            raise SnapshotIntegrityError("acquisition receipt file could not be read") from None
        try:
            receipt = parse_canonical_record(data, AcquisitionReceiptRecord)
        except (OSError, ValueError):
            raise SnapshotIntegrityError("acquisition receipt failed canonical validation") from None
        if canonical_record_hash(receipt) != expected_hash:
            raise SnapshotIntegrityError("acquisition receipt hash mismatch")
        return receipt

    def persist_receipt(self, receipt: AcquisitionReceiptRecord) -> str:
        self._validate_operational_dirs()
        receipt_hash = canonical_record_hash(receipt)
        target = self._receipts / f"{receipt_hash}.json"
        payload = canonical_record_bytes(receipt)
        with self._locked():
            try:
                os.lstat(target)
            except FileNotFoundError:
                pass
            except OSError:
                raise SnapshotIntegrityError("snapshot receipt path could not be accessed") from None
            else:
                self._verify_receipt_file(target, receipt_hash)
                return receipt_hash
            try:
                fd, temp_name = tempfile.mkstemp(prefix=".receipt-", suffix=".tmp", dir=self._staging)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.rename(temp_name, target)
                    _fsync_dir(self._receipts)
                finally:
                    try:
                        os.unlink(temp_name)
                    except FileNotFoundError:
                        pass
            except OSError:
                raise SnapshotIntegrityError("snapshot receipt persistence I/O failed") from None
        self._verify_receipt_file(target, receipt_hash)
        return receipt_hash

    def verify_receipt(self, receipt_sha256: str) -> AcquisitionReceiptRecord:
        self._validate_operational_dirs()
        if len(receipt_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in receipt_sha256
        ):
            raise SnapshotIntegrityError("acquisition receipt identity is malformed")
        return self._verify_receipt_file(
            self._receipts / f"{receipt_sha256}.json", receipt_sha256
        )

    def list_receipt_hashes(self) -> tuple[str, ...]:
        self._validate_operational_dirs()
        with self._locked():
            hashes: list[str] = []
            try:
                items = list(self._receipts.iterdir())
            except OSError:
                raise SnapshotIntegrityError("receipt inventory traversal failed") from None
            for item in items:
                _require_regular(item)
                if not item.name.endswith(".json"):
                    raise SnapshotIntegrityError("receipt inventory contains an unexpected file")
                receipt_hash = item.name[:-5]
                self.verify_receipt(receipt_hash)
                hashes.append(receipt_hash)
            return tuple(sorted(hashes))

    def verify_completed(self, observation_sha256: str) -> VerifiedSnapshot:
        self._validate_operational_dirs()
        if len(observation_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in observation_sha256
        ):
            raise SnapshotIntegrityError("completed observation identity is malformed")
        observation_path = self._observations / observation_sha256
        try:
            obs_exists = observation_path.exists()
        except OSError:
            raise SnapshotIntegrityError("completed observation access failed") from None
        if not obs_exists:
            raise SnapshotIntegrityError("completed observation is missing")
        observation = self._verify_observation_dir(observation_path, observation_sha256)
        snapshot_path = self._snapshots / observation.snapshot_state_sha256
        try:
            snap_exists = snapshot_path.exists()
        except OSError:
            raise SnapshotIntegrityError("semantic snapshot access failed") from None
        if not snap_exists:
            raise SnapshotIntegrityError("semantic snapshot referenced by observation is missing")
        state, representations = self._verify_snapshot_dir(
            snapshot_path, observation.snapshot_state_sha256
        )
        if state.authority_spec_sha256 != observation.authority_spec_sha256:
            raise SnapshotIntegrityError("persisted state and observation authority identities differ")
        state_entries = {entry.logical_path: entry for entry in state.entries}
        observation_entries = {entry.logical_path: entry for entry in observation.sources}
        if set(state_entries) != set(observation_entries):
            raise SnapshotIntegrityError("persisted state and observation inventories differ")
        for logical_path, entry in state_entries.items():
            observed = observation_entries[logical_path]
            if (
                entry.content_sha256 != observed.content_sha256
                or entry.representation_schema != observed.representation_schema
            ):
                raise SnapshotIntegrityError("persisted state and observation content identities differ")
        return VerifiedSnapshot(
            state=state,
            observation=observation,
            representations=representations,
        )
