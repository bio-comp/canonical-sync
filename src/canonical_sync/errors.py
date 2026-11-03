class CanonicalSyncError(RuntimeError):
    """Base exception for fail-closed canonical synchronization mechanics."""

    attempt_count: int | None = None


class AuthorityMismatchError(CanonicalSyncError):
    """An observed source does not match the declared authority profile."""


class SourceMovementError(CanonicalSyncError):
    """A source or exact membership changed during an acquisition attempt."""


class SnapshotIntegrityError(CanonicalSyncError):
    """A staged or persisted snapshot failed integrity verification."""


class GitPublicationError(CanonicalSyncError):
    """A mechanical Git publication operation failed safely."""


class RemoteRaceError(GitPublicationError):
    """The configured remote ref moved relative to the expected base."""


class RemoteVerificationError(GitPublicationError):
    """Published Git state could not be verified by exact remote readback."""


class TransportError(CanonicalSyncError):
    """Base exception for source-transport failures."""


class TransportAuthError(TransportError):
    """Authentication or credential discovery failed."""


class TransportPermissionError(TransportError):
    """The source principal lacks required read access."""


class TransportNotFoundError(TransportError):
    """A declared source object was not found or visible."""


class TransportTransientError(TransportError):
    """A bounded provider request exhausted transient retries."""


class TransportPermanentError(TransportError):
    """A non-retryable provider request failed."""


class UnsupportedRepresentationError(TransportPermanentError):
    """The requested source representation is not supported safely."""
