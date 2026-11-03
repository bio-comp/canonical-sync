from __future__ import annotations

from typing import Protocol

from .domain import AuthorityObjectSpec, SourceContent, SourceObservation, TransportProvenance


class SourceTransport(Protocol):
    """Protocol defining the interface for authority source transports.

    Transports are responsible for communicating with external authority providers
    (such as Google Drive) to observe metadata and read object content.
    Implementations must fail-closed on any unrecognized schema, network error,
    or authentication anomaly.
    """

    @property
    def provenance(self) -> TransportProvenance:
        """Return the immutable provenance metadata for this transport instance."""
        ...

    def observe(self, spec: AuthorityObjectSpec) -> SourceObservation:
        """Fetch remote object metadata for a given authority specification.

        Must raise CanonicalSyncError subclasses (e.g. ObjectNotFoundError,
        AuthorityMismatchError, TransportTransientError, TransportPermanentError)
        on observation failures.
        """
        ...

    def read(self, spec: AuthorityObjectSpec) -> SourceContent:
        """Fetch content bytes for an authority specification adhering to its schema.

        The `spec.representation_schema` determines the extraction and serialization
        contract:
          - Export schemas (e.g. `google-drive-export-markdown-v1`): convert native
            cloud-hosted documents (such as Google Docs) into canonical textual formats.
          - Binary download schemas (e.g. `google-drive-file-download-v1`): download
            raw, unmodified file bytes for binary or stored assets (e.g. PDFs, images,
            raw data tables).

        Transports must validate that the requested representation schema is supported
        for the target object's MIME type and must fail-closed (raising
        `TransportPermanentError` or `RepresentationSchemaError`) if an invalid or
        unsupported schema is requested.
        """
        ...

    def list_members(self, parent_id: str) -> tuple[SourceObservation, ...]:
        """Enumerate active child items directly contained in a container or folder."""
        ...
