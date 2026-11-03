"""Reusable verified canonical acquisition and publication mechanics."""

from .acquisition import (
    AcquisitionCandidate,
    acquire_stable_candidate,
    acquisition_provenance,
)
from .codec import (
    canonical_record_bytes,
    canonical_record_hash,
    parse_canonical_record,
)
from .domain import (
    AuthorityObjectSpec,
    AuthorityProfile,
    ExactMembershipSpec,
    SourceContent,
    SourceObservation,
    TransportProvenance,
    compute_authority_spec_sha256,
    profile_from_record,
)
from .errors import (
    AuthorityMismatchError,
    CanonicalSyncError,
    GitPublicationError,
    RemoteRaceError,
    RemoteVerificationError,
    SnapshotIntegrityError,
    SourceMovementError,
    TransportAuthError,
    TransportError,
    TransportNotFoundError,
    TransportPermanentError,
    TransportPermissionError,
    TransportTransientError,
    UnsupportedRepresentationError,
)
from .git_publication import (
    GitPublisher,
    PublicationFile,
    PublicationTree,
)
from .records import (
    AcquisitionProvenanceRecord,
    AcquisitionReceiptRecord,
    AuthorityObjectSpecRecord,
    AuthorityProfileRecord,
    AuthoritySpecificationRecord,
    ExactMembershipSpecRecord,
    GitPublicationReceiptRecord,
    SemanticEntryRecord,
    SnapshotObservationRecord,
    SnapshotStateRecord,
    SourceObservationRecord,
)
from .store import (
    SnapshotStore,
    StagedAcquisition,
)
from .transport import (
    SourceTransport,
)
from .workflow import (
    acquire_and_publish,
)

__all__ = [
    # Acquisition
    "AcquisitionCandidate",
    "acquire_stable_candidate",
    "acquisition_provenance",
    # Codec
    "canonical_record_bytes",
    "canonical_record_hash",
    "parse_canonical_record",
    # Domain
    "AuthorityObjectSpec",
    "AuthorityProfile",
    "ExactMembershipSpec",
    "SourceContent",
    "SourceObservation",
    "TransportProvenance",
    "compute_authority_spec_sha256",
    "profile_from_record",
    # Errors
    "AuthorityMismatchError",
    "CanonicalSyncError",
    "GitPublicationError",
    "RemoteRaceError",
    "RemoteVerificationError",
    "SnapshotIntegrityError",
    "SourceMovementError",
    "TransportAuthError",
    "TransportError",
    "TransportNotFoundError",
    "TransportPermanentError",
    "TransportPermissionError",
    "TransportTransientError",
    "UnsupportedRepresentationError",
    # Git Publication
    "GitPublisher",
    "PublicationFile",
    "PublicationTree",
    # Records
    "AcquisitionProvenanceRecord",
    "AcquisitionReceiptRecord",
    "AuthorityObjectSpecRecord",
    "AuthorityProfileRecord",
    "AuthoritySpecificationRecord",
    "ExactMembershipSpecRecord",
    "GitPublicationReceiptRecord",
    "SemanticEntryRecord",
    "SnapshotObservationRecord",
    "SnapshotStateRecord",
    "SourceObservationRecord",
    # Store
    "SnapshotStore",
    "StagedAcquisition",
    # Transport
    "SourceTransport",
    # Workflow
    "acquire_and_publish",
]
