from __future__ import annotations

import hashlib
import platform
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version

from .codec import canonical_record_hash
from .domain import AuthorityObjectSpec, AuthorityProfile, SourceContent, SourceObservation
from .errors import AuthorityMismatchError, CanonicalSyncError, SourceMovementError
from .records import (
    AcquisitionProvenanceRecord,
    SemanticEntryRecord,
    SnapshotObservationRecord,
    SnapshotStateRecord,
    SourceObservationRecord,
)
from .transport import SourceTransport


@dataclass(frozen=True, slots=True)
class AcquiredRepresentation:
    logical_path: str
    representation_schema: str
    data: bytes
    content_sha256: str


@dataclass(frozen=True, slots=True)
class AcquisitionCandidate:
    state: SnapshotStateRecord
    observation: SnapshotObservationRecord
    representations: tuple[AcquiredRepresentation, ...]
    attempt_count: int


def _validate_observation(spec: AuthorityObjectSpec, observed: SourceObservation) -> None:
    if observed.object_id != spec.object_id:
        raise AuthorityMismatchError("source object ID does not match declared authority")
    if observed.name != spec.expected_name:
        raise AuthorityMismatchError("source name does not match declared authority")
    if observed.mime_type != spec.expected_mime_type:
        raise AuthorityMismatchError("source MIME type does not match declared authority")
    if spec.expected_parent_id is not None and observed.parent_ids != (spec.expected_parent_id,):
        raise AuthorityMismatchError("source parent does not match declared authority")
    if observed.trashed:
        raise AuthorityMismatchError("declared authority source is trashed")


def _validate_content(spec: AuthorityObjectSpec, content: SourceContent) -> None:
    if content.representation_schema != spec.representation_schema:
        raise AuthorityMismatchError("source representation does not match declared authority")


def _membership_fingerprint(
    members: tuple[SourceObservation, ...],
) -> tuple[tuple[object, ...], ...]:
    return tuple(
        sorted(
            (member.movement_fingerprint for member in members),
            key=lambda item: str(item[0]),
        )
    )


def _observe_memberships(
    transport: SourceTransport,
    profile: AuthorityProfile,
    *,
    validate_expected: bool,
) -> dict[str, tuple[SourceObservation, ...]]:
    result: dict[str, tuple[SourceObservation, ...]] = {}
    for membership in profile.memberships:
        members = transport.list_members(membership.parent_id)
        ids = tuple(sorted(member.object_id for member in members))
        if validate_expected and ids != membership.expected_child_ids:
            raise AuthorityMismatchError("exact source membership does not match declared authority")
        for member in members:
            if member.parent_ids != (membership.parent_id,) or member.trashed:
                raise AuthorityMismatchError("exact source membership contains a moved or trashed object")
        result[membership.parent_id] = members
    return result


KNOWN_TRANSPORTS = frozenset({"google-drive-v3"})
KNOWN_TRANSPORT_VERSIONS = frozenset({"unknown", "injected-client"})
SAFE_AUTH_CATEGORIES = frozenset(
    {
        "injected-client",
        "test-injected",
        "adc:authorized-user",
        "adc:service-account",
        "adc:workload-identity",
        "adc:workload-identity-service-account",
    }
)


def _safe_transport_metadata(
    value: str, *, known: frozenset[str], numeric_version: bool = False
) -> str:
    if value in known or (numeric_version and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value)):
        return value
    return "opaque-sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def acquisition_provenance(transport: SourceTransport) -> AcquisitionProvenanceRecord:
    try:
        runner_version = version("canonical-sync")
    except PackageNotFoundError:
        runner_version = "uninstalled"
    transport_provenance = transport.provenance
    return AcquisitionProvenanceRecord(
        runner_name="canonical-sync",
        runner_version=runner_version,
        python_implementation=platform.python_implementation(),
        python_version=platform.python_version(),
        transport_name=_safe_transport_metadata(
            transport_provenance.transport_name, known=KNOWN_TRANSPORTS
        ),
        transport_version=_safe_transport_metadata(
            transport_provenance.transport_version,
            known=KNOWN_TRANSPORT_VERSIONS,
            numeric_version=True,
        ),
        auth_provenance=_safe_transport_metadata(
            transport_provenance.auth_provenance, known=SAFE_AUTH_CATEGORIES
        ),
    )


def _acquire_one_attempt(
    transport: SourceTransport,
    profile: AuthorityProfile,
    *,
    attempt_count: int,
    clock: Callable[[], datetime],
    provenance: AcquisitionProvenanceRecord,
) -> AcquisitionCandidate:
    pre: dict[str, SourceObservation] = {}
    for spec in profile.objects:
        observed = transport.observe(spec)
        _validate_observation(spec, observed)
        pre[spec.logical_path] = observed
    memberships_pre = _observe_memberships(transport, profile, validate_expected=True)

    representations: list[AcquiredRepresentation] = []
    by_path: dict[str, AcquiredRepresentation] = {}
    for spec in profile.objects:
        source = transport.read(spec)
        _validate_content(spec, source)
        representation = AcquiredRepresentation(
            logical_path=spec.logical_path,
            representation_schema=source.representation_schema,
            data=source.data,
            content_sha256=hashlib.sha256(source.data).hexdigest(),
        )
        representations.append(representation)
        by_path[spec.logical_path] = representation

    post: dict[str, SourceObservation] = {}
    for spec in profile.objects:
        observed = transport.observe(spec)
        _validate_observation(spec, observed)
        post[spec.logical_path] = observed
    memberships_post = _observe_memberships(transport, profile, validate_expected=False)

    for spec in profile.objects:
        if pre[spec.logical_path].movement_fingerprint != post[spec.logical_path].movement_fingerprint:
            raise SourceMovementError("source moved during acquisition attempt")
    for membership in profile.memberships:
        parent_id = membership.parent_id
        if _membership_fingerprint(memberships_pre[parent_id]) != _membership_fingerprint(
            memberships_post[parent_id]
        ):
            raise SourceMovementError("source membership moved during acquisition attempt")

    state = SnapshotStateRecord(
        authority_spec_sha256=profile.spec_sha256,
        entries=tuple(
            SemanticEntryRecord(
                logical_path=item.logical_path,
                representation_schema=item.representation_schema,
                content_sha256=item.content_sha256,
            )
            for item in representations
        ),
    )
    state_hash = canonical_record_hash(state)
    observation = SnapshotObservationRecord(
        snapshot_state_sha256=state_hash,
        authority_spec_sha256=profile.spec_sha256,
        acquired_at=clock(),
        attempt_count=attempt_count,
        provenance=provenance,
        sources=tuple(
            SourceObservationRecord(
                logical_path=spec.logical_path,
                object_id=post[spec.logical_path].object_id,
                name=post[spec.logical_path].name,
                mime_type=post[spec.logical_path].mime_type,
                version=post[spec.logical_path].version,
                modified_time=post[spec.logical_path].modified_time,
                parent_ids=post[spec.logical_path].parent_ids,
                trashed=post[spec.logical_path].trashed,
                can_download=post[spec.logical_path].can_download,
                representation_schema=by_path[spec.logical_path].representation_schema,
                content_sha256=by_path[spec.logical_path].content_sha256,
            )
            for spec in profile.objects
        ),
    )
    return AcquisitionCandidate(
        state=state,
        observation=observation,
        representations=tuple(sorted(representations, key=lambda item: item.logical_path)),
        attempt_count=attempt_count,
    )


def acquire_stable_candidate(
    transport: SourceTransport,
    profile: AuthorityProfile,
    *,
    max_movement_attempts: int = 3,
    clock: Callable[[], datetime] | None = None,
    provenance: AcquisitionProvenanceRecord | None = None,
) -> AcquisitionCandidate:
    if type(max_movement_attempts) is not int or max_movement_attempts < 1:
        raise ValueError("max_movement_attempts must be a positive integer")
    if not isinstance(profile, AuthorityProfile):
        raise TypeError("acquire_stable_candidate requires an AuthorityProfile")
    _ = profile.spec_sha256
    actual_clock = clock or (lambda: datetime.now(UTC))
    actual_provenance = provenance or acquisition_provenance(transport)
    last_movement: SourceMovementError | None = None
    for attempt in range(1, max_movement_attempts + 1):
        try:
            return _acquire_one_attempt(
                transport,
                profile,
                attempt_count=attempt,
                clock=actual_clock,
                provenance=actual_provenance,
            )
        except CanonicalSyncError as exc:
            exc.attempt_count = attempt
            if isinstance(exc, SourceMovementError):
                last_movement = exc
                if attempt == max_movement_attempts:
                    break
                continue
            raise
    assert last_movement is not None
    terminal_error = SourceMovementError("source moved during every bounded acquisition attempt")
    terminal_error.attempt_count = max_movement_attempts
    raise terminal_error from last_movement
